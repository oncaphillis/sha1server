#include <iostream>
#include <iomanip>
#include <exception>

#include <openssl/sha.h>
#include <ctype.h>
#include <stack>
#include <vector>
#include <functional>
#include <cmath>

// #define SMALL
// #define  CACHED

class Sha1Worker {

public:
    static const size_t FarmSize = 256;
    static const size_t KeySize = 20;
    typedef uint8_t key_t [KeySize];
    int _zeros = 0;
    std::string _prefix;
    std::string _suffix;
    SHA_CTX _ctx;
    std::vector<SHA_CTX> _ctxv;

public:
    Sha1Worker(const unsigned char *data,size_t len,size_t zeros=1)
        : _zeros(zeros)
        , _totals(0) {
        SHA1_Init(&_ctx);
        SHA1_Update(&_ctx,data,len);
        _prefix=std::string((char *)data,len);
        check(_ctx);
    }

    Sha1Worker(const std::string & s,size_t zeros)
        : Sha1Worker((unsigned char *)s.c_str(),s.length(),zeros) {
    }

    bool run() {
        std::function<bool (std::string s,
                            const std::vector<SHA_CTX> &,
                            std::vector<SHA_CTX> &,size_t,size_t & )> cached_algo =
                [&](std::string s,const std::vector<SHA_CTX> &vi,
            std::vector<SHA_CTX> &vo,size_t length,size_t  & total ) -> bool {
            for(const auto & chr : _alphabet) {
                s[length] = static_cast<char>(chr);
                if(length == s.length()-1) {
                    vo[total] = vi[total / _alphabet.size()];
                    SHA1_Update(&vo[total],&chr,1);
                    if( check(vo[total]) ) {
                        _suffix = s;
                        return true;
                    }
                    total++;
                } else{
                    if(cached_algo(s,vi,vo,length+1,total))
                        return true;
                }
            }
            return false;
        };

        std::function<bool (std::string s,const SHA_CTX &, size_t,size_t & )> plain_algo =
                [&](std::string s,const SHA_CTX & ctx,size_t length,size_t  & total ) -> bool {
            for(const auto & chr : _alphabet) {
                s[length] = static_cast<char>(chr);
                SHA_CTX cti = ctx;
                SHA1_Update(&cti,&chr,1);
                if(length == s.length()-1) {
                    if( check(cti) ) {
                        _suffix = s;
                        return true;
                    }
                    total++;
                } else{
                    if(plain_algo(s,cti,length+1,total)) {
                        return true;
                    }
                }
            }
            return false;
        };

        std::vector<SHA_CTX> vvi(1);
        vvi[0]=_ctx;
        for(int i=1;i<5;i++) {
            size_t t = 0;
#ifdef CACHED
            std::vector<SHA_CTX> vvo(::powl(_alphabet.size(),i));
            if(cached_algo(std::string(i,' '),vvi,vvo,0,t)) {
                _totals+=t;
                return true;
            }
            vvi.swap(vvo);
#else
            if(plain_algo(std::string(i,' '),_ctx,0,t)) {
                _totals+=t;
                return true;
            }
#endif
            _totals+=t;
        }
        return false;
    }

    const key_t & key() const {
        return _md;
    }

    const std::string  result() const {
        return _prefix+_suffix;
    }

    const std::string  & suffix() const {
        return _suffix;
    }

    const size_t & totals() const {
        return _totals;
    }

private:

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

    bool check(const SHA_CTX & c) {
        SHA_CTX ctxr = c;
        SHA1_Final(_md, &ctxr);
        for(int i=0;i<_zeros/2;i++) {
            if(_md[i]!=0)
                return false;
        }
        if((_zeros % 2)!=0) {
            return (_md[ _zeros / 2 ] & 0xf0) == 0x00;
        }
        return true;
    }
    static const std::vector<uint8_t> _alphabet;
    size_t _totals;
    key_t _md;
};

const std::vector<uint8_t> Sha1Worker::_alphabet(Sha1Worker::alphabet());

int main()
{
    Sha1Worker sm("gbcHqTYxBWjOecmSYutcoDyiMTpgVjUCSqEoucgjDiVNmXuowGkIbpwmYWdWLkpv",7);
    //Sha1Worker sm("prefiX",3);
    time_t t0 = ::time(nullptr);
    if(sm.run()) {

        std::cerr << sm.totals() << " in " << ::time(nullptr)-t0 << " sec " << std::endl;

        std::cerr << std::endl << " +@+@+ <" << sm.result() << "> " << std::endl;

        std::cerr << " -0- ";
        for( const auto & c : sm.key() ) {
            std::cerr << std::hex << std::setw(2) << std::setfill('0') << (int)c;
        }
        std::cerr << std::endl;

        Sha1Worker::key_t m;

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
