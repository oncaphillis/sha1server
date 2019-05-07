#include "sha1farm.h"
#include <iostream>

#if 0

#include <iostream>
#include <iomanip>
#include <exception>


#include <ctype.h>
#include <stack>
#include <vector>
#include <functional>
#include <cmath>
#include <thread>

#include <mutex>
#include <map>
#include <boost/multiprecision/cpp_int.hpp>
#include <openssl/sha.h>

class Sha1Farm {
public:
    static const size_t KeySize = 20;
    typedef uint8_t key_t [KeySize];
private:
    typedef __int128 idx_t;
    static const idx_t streakSize = 10000000;
    idx_t _currentStreak = 0;
    idx_t _totals = 0;
    std::vector<std::auto_ptr<std::thread>> _farm;
    size_t _zeros = 0;
    std::string _prefix;
    SHA_CTX _ctx;
    std::map<long long,key_t> _results;
    std::mutex _mtx;
    bool _stopWatch=false;

public:
    Sha1Farm(const unsigned char *data,size_t len,size_t zeros=1)
        : _zeros(zeros) {
        SHA1_Init(&_ctx);
        SHA1_Update(&_ctx,data,len);
        _prefix=std::string((char *)data,len);
        key_t k;
        if( check(_ctx,k,zeros)) {
            std::copy(std::begin(k),std::end(k),std::begin(_results[-1]));
        }
    }

    Sha1Farm(const std::string & s,size_t zeros)
        : Sha1Farm((unsigned char *)s.c_str(),s.length(),zeros) {
    }

    bool run(int farmsize=8) {
        if(!sucess()) {
            std::thread watch(&Sha1Farm::watch,this);

            for(int i=0;i<farmsize;i++) {
                _farm.push_back(std::auto_ptr<std::thread>(new std::thread(&Sha1Farm::crunch,this,_ctx,_zeros)));
            }
            for(auto & t : _farm) {
                t->join();
            }
            {
                std::lock_guard<std::mutex> lck(_mtx);
                _stopWatch = true;
            }
            watch.join();
        }
        return true;
    }

    bool sucess()   {
        std::lock_guard<std::mutex> _lck(_mtx);
        return !_results.empty();
    }

    const key_t  & key()   {
        std::lock_guard<std::mutex> _lck(_mtx);
        return _results.empty() ? _dummy_key : _results.begin()->second;
    }

    const std::string  result()  {
        return prefix()+suffix();
    }

    const std::string  & prefix() const {
        return _prefix;
    }

    const std::string  suffix()  {
        std::lock_guard<std::mutex> _lck(_mtx);
        return _results.empty() ? "" : buildString(_results.begin()->first);
    }

    const long long  totals()  {
        std::lock_guard<std::mutex> _lck(_mtx);
        return _totals;
    }

    const std::string  dump(const std::string & s) {
        std::stringstream ss;
        for( auto c : s) {
            if(c>31)
                std::cerr << c;
            else
                std::cerr << "\\x" << std::hex << std::setw(2) << std::setfill('0')
                          << (static_cast<unsigned int>(c) & 0xff) ;
        }
        return ss.str();
    }

private:
    void watch() {
        int i=0;
        time_t t0 = ::time(nullptr);
        const char r[]={'-','\\','|','/'};
        while(true) {
            sleep(1);
            idx_t to;
            time_t t1 = ::time(nullptr);
            {
                std::lock_guard<std::mutex> lck(_mtx);
                to = _totals;
                if(_stopWatch)
                    break;
            }
            int m=0;
            int h=0;
            int s=0;

            h =  (t1-t0) / (60*60);
            m = ((t1-t0) - h*(60*60))/60;
            s =  (t1-t0) - h*(60*60) - m*60;

            std::cerr << "\r\033[2K" << r[i] << " "
                      << std::setw(20) << (long long)to
                      << " "
                      << std::setfill('0')
                      << std::setw(2) << h << ":"
                      << std::setw(2) << m << ":"
                      << std::setw(2) << s << " "
                      << std::setfill(' ')
                      << " " << double(to) / (t1-t0) << "/sec" << std::flush;
            i++;
            i = i>3 ? 0 : i;
        }

        idx_t to;
        time_t t1 = ::time(nullptr);
        {
            std::lock_guard<std::mutex> lck(_mtx);
            to = _totals;
        }

        int m=0;
        int h=0;
        int s=0;

        h =  (t1-t0) / (60*60);
        m = ((t1-t0) - h*(60*60))/60;
        s =  (t1-t0) - h*(60*60) - m*60;

        std::cerr << "\r\033[2K"
                  << "*"
                  << std::setw(20) << (long long)to << " in "
                 << " "
                 << std::setfill('0')
                 << std::setw(2) << h << ":"
                 << std::setw(2) << m << ":"
                 << std::setw(2) <<  s << " "
                 << std::setfill(' ')
                 << " " << double(to) / (t1-t0) << "/sec" << std::endl;
    }

    void crunch(const SHA_CTX ctx,size_t zeros) {

        idx_t current = 0;
        idx_t total = 0;
        idx_t streakStart;

        while( true ) {
            {
                std::lock_guard<std::mutex> lck(_mtx);
                _totals += total;
                if(!_results.empty()) {
                    break;
                }
                streakStart = _currentStreak;
                _currentStreak += streakSize;
            }

            for(idx_t crt = streakStart;crt<streakStart+streakSize;crt++) {
                std::string s = buildString(crt);

                SHA_CTX ctxi = ctx;
                SHA1_Update(&ctxi,s.c_str(),s.length());
                key_t k;
                if(check(ctxi,k,zeros)) {
                    std::lock_guard<std::mutex> lck(_mtx);
                    std::copy(std::begin(k),std::end(k),std::begin(_results[crt]));
                    _totals += total;
                    return;
                }
                total++;
            }
        }
    }

    static const std::vector<uint8_t>  alphabet() {
        std::vector<uint8_t> _a;
#ifdef SMALL
        for(uint8_t c='a';c<'d';c++) {
#else
        for(uint8_t c=1;c>0;c++) {
#endif
            if(c!='\r' && c!='\t' && c!='\n') {
                _a.push_back(c);
            }
        }
        return _a;
    }

    static std::string buildString(idx_t c) {
        std::string s;
        do {
            s += _alphabet[ static_cast<size_t> (c % _alphabet.size()) ];
            c  = (c / _alphabet.size()) - 1;
        } while(c >= 0);
        return s;
    }

    static bool check(const SHA_CTX & c,key_t &m,size_t zeros) {
        SHA_CTX ctxr = c;
        SHA1_Final(m, &ctxr);
        for(int i=0;i<zeros/2;i++) {
            if(m[i]!=0)
                return false;
        }
        if((zeros % 2)!=0) {
            return (m[ zeros / 2 ] & 0xf0) == 0x00;
        }
        return true;
    }

    static const std::vector<uint8_t> _alphabet;
    key_t _dummy_key {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
};

const std::vector<uint8_t> Sha1Farm::_alphabet(Sha1Farm::alphabet());
#endif

int main()
{


    Sha1Farm sm("gbcHqTYxBWjOecmSYutcoDyiMTpgVjUCSqEoucgjDiVNmXuowGkIbpwmYWdWLkpv",9);

    std::cerr << sizeof (long long) << std::endl;

    if(sm.run()) {
        std::cerr << " =A= '" << sm.dump(sm.result()) << "'" << std::endl;

        std::cerr << " -0- " ;
        for( const auto & c : sm.key() ) {
            std::cerr << std::hex << std::setw(2) << std::setfill('0') << (int)c;
        }
        std::cerr << std::endl;

        Sha1Farm::key_t m;

        SHA_CTX c;
        SHA1_Init(&c);
        SHA1_Update(&c,sm.result().c_str(),sm.result().length());
        SHA1_Final(m,&c);

        std::cerr << " -1- ";
        for( const auto & c : m ) {
            std::cerr << std::hex << std::setw(2) << std::setfill('0') << (int)c;
        }

        std::cerr << std::endl;
        std::cerr << sm.suffix().length() << std::endl;
    }
}
