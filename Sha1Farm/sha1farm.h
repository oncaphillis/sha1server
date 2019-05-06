#ifndef SHA1FARM_H
#define SHA1FARM_H

#include <openssl/sha.h>

#include <thread>
#include <mutex>
#include <map>

#include <boost/multiprecision/cpp_int.hpp>

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
    const std::string  dump(const std::string & s);
    static std::string sha1(const std::string & s);
    inline
    static std::string buildString(idx_t c)  {
        char b[30];
        return std::string(b,buildString(c,b));
    }

private:
    void watch();
    void crunch(const SHA_CTX ctx,size_t zeros);
    static const std::vector<uint8_t>  alphabet();

    inline
    static size_t buildString(idx_t c, char *b)  {
        size_t as = _alphabet.size();
        int o=0;
        do {
            b[o++] = _alphabet[ static_cast<size_t> (c % as) ];
            c  = (c / as) - 1;
        } while(c >= 0);
        return o;
    }


    static bool check(const SHA_CTX & c,key_t &m,size_t zeros);

    static const std::vector<uint8_t> _alphabet;
    key_t _dummy_key {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
};

#endif // SHA1FARM_H
