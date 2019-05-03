#include <iostream>
#include <iomanip>
#include <exception>

#include <openssl/sha.h>
#include <ctype.h>
#include <stack>
#include <vector>


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
        : Sha1Worker((unsigned char *)s.c_str(),s.length(),zeros) {
    }

    bool run(std::string s="") {
        if(!_alphabet.empty()) {
            while(true)  {
                s += (char)_alphabet[0];
                for(int i=0;i<s.length();i++) {
                    for(auto c : _alphabet) {
                        s[i] = (char)c;
                        std::cerr << "'" << s << "'" << std::endl;
                    }
                }
            }
        }
        return true;
    }

    const key_t & key() const {
        return _md;
    }

    const std::string & result() const {
        return _result;
    }

private:
    static const std::vector<uint8_t>  alphabet() {
        std::vector<uint8_t> _a;
        for(uint8_t c='a';c<='c';c++) {
            if(c!='\r' && c!='\t' && c!='\n') {
                _a.push_back(c);
            }
        }
        return _a;
    }

    bool run(const SHA_CTX & ctxi,std::string s,bool ex=true) {

        for(const auto & c : _alphabet) {
            SHA_CTX ctxr = ctxi;
            SHA1_Update(&ctxr,&c,1);
            std::cerr << "*"
                         "'" << (s+static_cast<char>(c)) << "'" << std::endl;
            if( check(ctxr) ) {
                _result = s + static_cast<char>(c) ;
                return true;
            }
        }

        std::cerr << " ----------- " << ex << std::endl;

        if(ex) {
            for(const auto & c : _alphabet) {
                SHA_CTX ctxr = ctxi;
                SHA1_Update(&ctxr,&c,1);
                if(run(ctxr,s+static_cast<char>(c),false)) {
                    return true;
                }
            }
        }
        return false;
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
    static const std::vector<uint8_t> _alphabet;
    key_t _md;
};

const std::vector<uint8_t> Sha1Worker::_alphabet(Sha1Worker::alphabet());

int main()
{
    // Sha1Machine sm("gbcHqTYxBWjOecmSYutcoDyiMTpgVjUCSqEoucgjDiVNmXuowGkIbpwmYWdWLkpv",9);
    Sha1Worker sm("X",3);
    sm.run();
    ::exit(1);

    std::cerr << " -- ";
    for( const auto & c : sm.key() ) {
        std::cerr << std::hex << std::setw(2) << std::setfill('0') << (int)c;
    }
    std::cerr << std::endl << " +@+@+ " << sm.result() << " " << std::endl;
}
