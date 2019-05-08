#define SWAP32(a)	(as_uint(as_uchar4(a).wzyx))

#define K0  0x5A827999
#define K1  0x6ED9EBA1
#define K2  0x8F1BBCDC
#define K3  0xCA62C1D6

#define H1 0x67452301
#define H2 0xEFCDAB89
#define H3 0x98BADCFE
#define H4 0x10325476
#define H5 0xC3D2E1F0

#ifndef uint32_t
#define uint32_t unsigned int
#endif

uint32_t SHA1CircularShift(int bits, uint32_t word)
{
	return ((word << bits) & 0xFFFFFFFF) | (word) >> (32 - (bits));
}
#if 0
__constant uint alphaSize  = 3;
__constant char alphabet[alphaSize]={0x30,0x31,0x32};
#else
__constant char alphabet[]={1,2,3,4,5,6,7,8,11,12,14,15,16,
                          17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,
                          33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,
                          49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,64,
                          65,66,67,68,69,70,71,72,73,74,75,76,77,78,79,80,
                          81,82,83,84,85,86,87,88,89,90,91,92,93,94,95,96,
                          97,98,99,100,101,102,103,104,105,106,107,108,109,
                          110,111,112,113,114,115,116,117,118,119,120,121,
                          122,123,124,125,126,127,128,129,130,131,132,133,
                          134,135,136,137,138,139,140,141,142,143,144,145,
                          146,147,148,149,150,151,152,153,154,155,156,157,
                          158,159,160,161,162,163,164,165,166,167,168,169,
                          170,171,172,173,174,175,176,177,178,179,180,181,
                          182,183,184,185,186,187,188,189,190,191,192,193,
                          194,195,196,197,198,199,200,201,202,203,204,205,
                          206,207,208,209,210,211,212,213,214,215,216,217,
                          218,219,220,221,222,223,224,225,226,227,228,229,
                          230,231,232,233,234,235,236,237,238,239,240,241,
                          242,243,244,245,246,247,248,249,250,251,252,253,
                          254,255};
__constant uint alphaSize  = 252;
#endif

void sha1_crypt(uint ulen, __global char *plain_key,  __global uint *digest) {
    int t, gid, msg_pad;
    int stop, mmod;
    uint i, item, total;
    uint W[80], temp, A,B,C,D,E;
	int current_pad;

	msg_pad=0;

	total = ulen%64>=56?2:1 + ulen/64;

	//printf("ulen: %u total:%u\n", ulen, total);

    digest[0] = 0x67452301;
	digest[1] = 0xEFCDAB89;
	digest[2] = 0x98BADCFE;
	digest[3] = 0x10325476;
	digest[4] = 0xC3D2E1F0;
	for(item=0; item<total; item++)
	{

		A = digest[0];
		B = digest[1];
		C = digest[2];
		D = digest[3];
		E = digest[4];

	#pragma unroll
		for (t = 0; t < 80; t++){
		W[t] = 0x00000000;
		}
		msg_pad=item*64;
		if(ulen > msg_pad)
		{
			current_pad = (ulen-msg_pad)>64?64:(ulen-msg_pad);
		}
		else
		{
			current_pad =-1;		
		}

		if(current_pad>0)
		{
			i=current_pad;

			stop =  i/4;

            for (t = 0 ; t < stop ; t++){
				W[t] = ((uchar)  plain_key[msg_pad + t * 4]) << 24;
				W[t] |= ((uchar) plain_key[msg_pad + t * 4 + 1]) << 16;
				W[t] |= ((uchar) plain_key[msg_pad + t * 4 + 2]) << 8;
				W[t] |= (uchar)  plain_key[msg_pad + t * 4 + 3];
			}
			mmod = i % 4;
			if ( mmod == 3){
				W[t] = ((uchar)  plain_key[msg_pad + t * 4]) << 24;
				W[t] |= ((uchar) plain_key[msg_pad + t * 4 + 1]) << 16;
				W[t] |= ((uchar) plain_key[msg_pad + t * 4 + 2]) << 8;
				W[t] |=  ((uchar) 0x80) ;
			} else if (mmod == 2) {
				W[t] = ((uchar)  plain_key[msg_pad + t * 4]) << 24;
				W[t] |= ((uchar) plain_key[msg_pad + t * 4 + 1]) << 16;
				W[t] |=  0x8000 ;
			} else if (mmod == 1) {
				W[t] = ((uchar)  plain_key[msg_pad + t * 4]) << 24;
				W[t] |=  0x800000 ;
            } else  {
				W[t] =  0x80000000 ;
			}
			
			if (current_pad<56)
			{
				W[15] =  ulen*8 ;
			}
		}
		else if(current_pad <0)
		{
			if( ulen%64==0)
				W[0]=0x80000000;
			W[15]=ulen*8;
		}

		for (t = 16; t < 80; t++)
		{
			W[t] = SHA1CircularShift(1, W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16]);
		}

		for (t = 0; t < 20; t++)
		{
			temp = SHA1CircularShift(5, A) +
				((B & C) | ((~B) & D)) + E + W[t] + K0;
			temp &= 0xFFFFFFFF;
			E = D;
			D = C;
			C = SHA1CircularShift(30, B);
			B = A;
			A = temp;
		}

		for (t = 20; t < 40; t++)
		{
			temp = SHA1CircularShift(5, A) + (B ^ C ^ D) + E + W[t] + K1;
			temp &= 0xFFFFFFFF;
			E = D;
			D = C;
			C = SHA1CircularShift(30, B);
			B = A;
			A = temp;
		}

		for (t = 40; t < 60; t++)
		{
			temp = SHA1CircularShift(5, A) +
				((B & C) | (B & D) | (C & D)) + E + W[t] + K2;
			temp &= 0xFFFFFFFF;
			E = D;
			D = C;
			C = SHA1CircularShift(30, B);
			B = A;
			A = temp;
		}

		for (t = 60; t < 80; t++)
		{
			temp = SHA1CircularShift(5, A) + (B ^ C ^ D) + E + W[t] + K3;
			temp &= 0xFFFFFFFF;
			E = D;
			D = C;
			C = SHA1CircularShift(30, B);
			B = A;
			A = temp;
		}

		digest[0] = (digest[0] + A) & 0xFFFFFFFF;
		digest[1] = (digest[1] + B) & 0xFFFFFFFF;
		digest[2] = (digest[2] + C) & 0xFFFFFFFF;
		digest[3] = (digest[3] + D) & 0xFFFFFFFF;
		digest[4] = (digest[4] + E) & 0xFFFFFFFF;

	}
}

bool sha1_permut(__global char *c,int *length,__global uint *digest,int zeros) {

    for(int i = 0 ; i < 256 ; i++) {
        int j = 0;
        while(true) {
            ++c[ j ];
            while(c[j] == '\r' || c[j] == '\n' || c[j] == '\t' ) {
                ++c[ j ];
            }
            if( c[ j ] == 0 ) {
                c[j]=1;
                j++;
            } else {
                break;
            }
            if( j == *length ) {
                c[j]=1;
                (*length)++;
                break;
            }
        };

        c[ *length ] = '@';

        sha1_crypt(*length, c, digest);
        
        int k=0;
        int n=0;
        for(k=0;k<5;k++) {
         uint a = digest[k];
         int l;
         for(l=0;l<8;l++) {
          if( (a & 0xf0000000) != 0x00000000 ) {
           break;
          }
          n++;
          a <<= 4;
         }
         if(l!=7) {
          break;
         }
       }
       if(n>=zeros) {
        return true;
       }
    }
    return false;
}

__kernel void sha1_multi(__global uint *data_info,
                         __global char *plain_key,
                         __global uint *digest) {
    plain_key[0]=0;
    int length = 1;
    for(long i = 0 ; i < 256  ; i++) {
     if(sha1_permut(plain_key,&length,digest,6))
      return;
    }
}
