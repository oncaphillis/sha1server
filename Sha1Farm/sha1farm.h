#ifndef SHA1FARM_H
#define SHA1FARM_H

#include <openssl/sha.h>

#include <thread>
#include <mutex>
#include <map>

#include <boost/multiprecision/gmp.hpp>

class Sha1Farm {
public:
    static const size_t KeySize = 20;
    typedef uint8_t key_t [KeySize];
private:
    typedef boost::multiprecision::mpz_int idx_t;
    static const long long streakSize = 10000000L;
    idx_t _currentStreak = 0;
    idx_t _totals = 0;
    std::vector<std::auto_ptr<std::thread>> _farm;
    size_t _zeros = 0;
    std::string _prefix;
    SHA_CTX _ctx;
    std::map<idx_t,key_t> _results;
    mutable std::mutex _mtx;
    bool _stopWatch=false;
public:
    Sha1Farm(const unsigned char *data,size_t len,size_t zeros=1);
    Sha1Farm(const std::string & s,size_t zeros);
    bool run(int farmsize=8);
    bool sucess() const;
    const key_t & key() const;
    const std::string  result() const;
    const std::string  & prefix() const;
    const std::string  suffix() const ;
    const idx_t  totals() const;

    static const std::string  dump(const std::string & s);
    static std::string sha1(const std::string & s);

    inline
    static std::string buildString(idx_t c)  {
        std::string s;
        size_t as = _alphabet.size();
        do {
            s+= _alphabet[ static_cast<size_t> (c % as) ];
            c  = (c / as) - 1;
        } while(c >= 0);
        return s;
    }

    inline
    static std::string & incrementString(std::string & s)  {
        int i=0;
        while(true) {
            ++s[i];
            while( s[i] == '\t' || s[i] == '\r' || s[i] == '\n'  )
                ++s[i];
            if(s[i]==0) {
                s[i]=1;
                i++;
            } else {
                break;
            }
            if(i==s.length()) {
                s+=1;
                break;
            }
        }
        return s;
    }

private:
    void watch();
    void crunch(const SHA_CTX ctx,size_t zeros);
    static const std::vector<uint8_t>  alphabet();
    static bool check(const SHA_CTX & c,key_t &m,size_t zeros);

    static const std::vector<uint8_t> _alphabet;
    key_t _dummy_key {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
};

#endif // SHA1FARM_H
