#include "sha1farm.h"

#include <iostream>
#include <iomanip>
#include <exception>

#include <ctype.h>
#include <vector>
#include <cmath>

const std::vector<uint8_t> Sha1Farm::_alphabet(Sha1Farm::alphabet());

Sha1Farm::Sha1Farm(const unsigned char *data,size_t len,size_t zeros)
    : _zeros(zeros) {
    SHA1_Init(&_ctx);
    SHA1_Update(&_ctx,data,len);
    _prefix=std::string((char *)data,len);
    key_t k;
    if( check(_ctx,k,zeros)) {
        std::copy(std::begin(k),std::end(k),std::begin(_results[-1]));
    }
}

Sha1Farm::Sha1Farm(const std::string & s,size_t zeros)
    : Sha1Farm((unsigned char *)s.c_str(),s.length(),zeros) {
}

bool Sha1Farm::run(int farmsize) {
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

bool Sha1Farm::sucess()   const {
    std::lock_guard<std::mutex> _lck(_mtx);
    return !_results.empty();
}

const Sha1Farm::key_t  & Sha1Farm::key() const  {
    std::lock_guard<std::mutex> _lck(_mtx);
    return _results.empty() ? _dummy_key : _results.begin()->second;
}

const std::string  Sha1Farm::result() const {
    return prefix()+suffix();
}

const std::string  & Sha1Farm::prefix() const {
    return _prefix;
}

const std::string  Sha1Farm::suffix() const  {
    std::lock_guard<std::mutex> _lck(_mtx);
    return _results.empty() ? "" : buildString(_results.begin()->first);
}

const Sha1Farm::idx_t  Sha1Farm::totals() const {
    std::lock_guard<std::mutex> _lck(_mtx);
    return _totals;
}

const std::string  Sha1Farm::dump(const std::string & s) {
    std::stringstream ss;
    for( auto c : s) {
        if(c>31 && c<0x7f)
            ss << c;
        else
            ss << "\\x" << std::hex << std::setw(2) << std::setfill('0')
                      << (static_cast<unsigned int>(c) & 0xff) ;
    }
    return ss.str();
}

std::string Sha1Farm::sha1(const std::string &s)
{
    std::stringstream ss;

    SHA_CTX ctx;
    SHA1_Init(&ctx);
    SHA1_Update(&ctx,s.c_str(),s.length());
    key_t md;
    SHA1_Final(md,&ctx);

    for( const auto & c : md ) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)c;
    }

    return ss.str();
}

void Sha1Farm::watch() {
    int i=0;
    time_t t0 = ::time(nullptr);
    const char r[]={'-','\\','|','/'};

    idx_t str;
    while(true) {
        sleep(1);
        idx_t to;
        time_t t1 = ::time(nullptr);
        {
            std::lock_guard<std::mutex> lck(_mtx);
            to = _totals;
            str = _currentStreak;
            if(_stopWatch)
                break;
        }

        int m=0;
        int h=0;
        int s=0;

        h =  (t1-t0) / (60*60);
        m = ((t1-t0) - h*(60*60))/60;
        s =  (t1-t0) - h*(60*60) - m*60;
        std::string p = buildString(str);
        std::cerr << "\r\033[2K" << r[i] << " "
                  << std::setw(20) << (long long)to
                  << " "
                  << p.length() << " <" << ::pow(252,p.length()) << ">" << std::setw(30) << dump(p)
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

void Sha1Farm::crunch(const SHA_CTX ctx,size_t zeros) {

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

        std::string str = buildString(streakStart);

        for(idx_t crt = streakStart;crt<streakStart+streakSize;crt++) {

            SHA_CTX ctxi = ctx;
            SHA1_Update(&ctxi,str.c_str(),str.length());
            key_t k;
            if(check(ctxi,k,zeros)) {
                std::lock_guard<std::mutex> lck(_mtx);
                std::copy(std::begin(k),std::end(k),std::begin(_results[crt]));
                _totals += total;
                return;
            }
            incrementString(str);
            total++;
        }
    }
}

const std::vector<uint8_t>  Sha1Farm::alphabet() {
    std::vector<uint8_t> _a;
    for(uint8_t c=1;c>0;c++) {
        if(c!='\r' && c!='\t' && c!='\n') {
            _a.push_back(c);
        }
    }
    return _a;
}

bool Sha1Farm::check(const SHA_CTX & c,Sha1Farm::key_t &m,size_t zeros) {
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

