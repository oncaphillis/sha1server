#include <iostream>
#include <iomanip>
#include <exception>

#include <openssl/sha.h>
#include <ctype.h>
#include <stack>

int _m=0;

class Sha1Worker {
public:
    static const size_t FarmSize = 256;
    static const size_t KeySize = 20;
    typedef uint8_t key_t [KeySize];

    bool _success = false;
    int _zeros = 0;
    std::string _result;
    SHA_CTX _ctx;
    std::stack<SHA_CTX> _ctxv;

public:
    Sha1Worker(const unsigned char *data,size_t len,size_t zeros=1)
        : _zeros(zeros) {
        SHA1_Init(&_ctx);
        SHA1_Update(&_ctx,data,len);
        _result=std::string((char *)data,len);
        check(_ctx);
    }

    Sha1Worker(const std::string & s,size_t zeros)
        : Sha1Machine((unsigned char *)s.c_str(),s.length(),zeros) {
    }

    bool run() {
        return run(_ctx,_result);

    }

    const key_t & key() const {
        return _md;
    }

    const std::string & result() const {
        return _result;
    }

private:

    bool run(const SHA_CTX & ctxi,std::string s,int r=0) {

        if(r > _m) {
            _m = r;
        }

        for(int i='a';i<'z';i++) {
            uint8_t c=uint8_t(i);
            SHA_CTX ctxr = ctxi;
            SHA1_Update(&ctxr,&c,1);
            std::cerr << "'" << s+(char)c << "'" << std::endl;
            if( check(ctxr) ) {
                _result = s+(char)c;
                return true;
            }
        }

        std::cerr << "------------------------" << std::endl;

        for(int i='a';i<'z';i++) {
            SHA_CTX ctxr = ctxi;
            uint8_t c = uint8_t(i);
            SHA1_Update(&ctxr,&c,1);
            if(run(ctxr,s+(char)c,r+1)) {
                return true;
            }
        }
    }

    bool check(const SHA_CTX & c) {

        if(_success)
            return true;

        SHA_CTX ctxr = c;
        SHA1_Final(_md, &ctxr);

        int n=0;

        for(const auto & c : _md) {
            if(n >=_zeros ||  ((c & 0xf0) !=0) )
                break;
            n++;

            if(n >=_zeros ||  ((c & 0x0f) !=0) )
                break;
            n++;
        }

        if(n >= _zeros) {
            _success = true;
            for( const auto & c : _md ) {
                std::cerr << std::hex << std::setw(2) << std::setfill('0') << (int)c;
            }
            return true;
        }
        return false;
    }
    key_t _md;
};

int main()
{
    // Sha1Machine sm("gbcHqTYxBWjOecmSYutcoDyiMTpgVjUCSqEoucgjDiVNmXuowGkIbpwmYWdWLkpv",9);
    Sha1Worker sm("X",9);
    sm.run();

    std::cerr << " -- ";
    for( const auto & c : sm.key() ) {
        std::cerr << std::hex << std::setw(2) << std::setfill('0') << (int)c;
    }
    std::cerr << std::endl << " +@+@+ " << sm.result() << " " << sm.key()  << std::endl;
}
