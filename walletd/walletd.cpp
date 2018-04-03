#include <stdio.h>
#include "include/a.h"
#include "readcfg.h"
#include "walletd.h"
#include <string>
#include "loopbuf.h"
#include "wallet_pdu.h"

#include "key.h"
#include "utilstrencodings.h"
#include "initwallet.h"
#include "messagesigner.h"
#include <secp256k1_ecdh.h>
#include <secp256k1.h>
#include "base58.h"
#include <boost/assign/list_of.hpp>



using namespace std;

enum Base58Type {
        PUBKEY_ADDRESS,
        SCRIPT_ADDRESS,
        SECRET_KEY,     // BIP16
        EXT_PUBLIC_KEY, // BIP32
        EXT_SECRET_KEY, // BIP32
        EXT_COIN_TYPE,  // BIP44

        MAX_BASE58_TYPES
    };

std::vector<unsigned char> base58Prefixes[MAX_BASE58_TYPES];

// Testnet Ulord addresses start with 'u'
base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,130);
// Testnet Ulord script addresses start with 's'
base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,125);
// Testnet private keys start with '9' or 'c'(as in Bitcoin)
base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,0xef);
// Testnet Ulord BIP32 pubkeys start with 'tpub' (Bitcoin defaults)
base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x35)(0x87)(0xCF).convert_to_container<std::vector<unsigned char> >();
// Testnet Ulord BIP32 prvkeys start with 'tprv' (Bitcoin defaults)
base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x35)(0x83)(0x94).convert_to_container<std::vector<unsigned char> >();
// Testnet Ulord BIP44 coin type is '1' (All coin's testnet default)
base58Prefixes[EXT_COIN_TYPE]  = boost::assign::list_of(0x80)(0x00)(0x00)(0x01).convert_to_container<std::vector<unsigned char> >();

std::string EncodeBase58(const unsigned char* pbegin, const unsigned char* pend)
{
    // Skip & count leading zeroes.
    int zeroes = 0;
    while (pbegin != pend && *pbegin == 0) {
        pbegin++;
        zeroes++;
    }
    // Allocate enough space in big-endian base58 representation.
    std::vector<unsigned char> b58((pend - pbegin) * 138 / 100 + 1); // log(256) / log(58), rounded up.
    // Process the bytes.
    while (pbegin != pend) {
        int carry = *pbegin;
        // Apply "b58 = b58 * 256 + ch".
        for (std::vector<unsigned char>::reverse_iterator it = b58.rbegin(); it != b58.rend(); it++) {
            carry += 256 * (*it);
            *it = carry % 58;
            carry /= 58;
        }
        assert(carry == 0);
        pbegin++;
    }
    // Skip leading zeroes in base58 result.
    std::vector<unsigned char>::iterator it = b58.begin();
    while (it != b58.end() && *it == 0)
        it++;
    // Translate the result into a string.
    std::string str;
    str.reserve(zeroes + (b58.end() - it));
    str.assign(zeroes, '1');
    while (it != b58.end())
        str += pszBase58[*(it++)];
    return str;
}

std::string EncodeBase58(const std::vector<unsigned char>& vch)
{
    return EncodeBase58(&vch[0], &vch[0] + vch.size());
}

std::string EncodeBase58Check(const std::vector<unsigned char>& vchIn)
{
    // add 4-byte hash check to the end
    std::vector<unsigned char> vch(vchIn);
    uint256 hash = Hash(vch.begin(), vch.end());
    vch.insert(vch.end(), (unsigned char*)&hash, (unsigned char*)&hash + 4);
    return EncodeBase58(vch);
}


void printhelp()
{
       cout<<"1  help  :"  <<endl;
       cout<<"2  getnewaddreess"<<endl;
       cout<<"3  dumpwallet"<<endl;
       cout<<"4  dumpprivkey  address"<<endl;
       cout<<"5  importprivkey prikey "<<endl;
       cout<<"6  importwallets"<<endl;

}


int main(int argc, char* argv[])
{

   string  dbuser ,dbhost, dbpass;
   int startheight, endheight;
   readcfg(startheight,endheight,dbuser,dbhost,dbpass);
  
    Secp256k1Init ecc("main");
    initwallet();

    
    if(argc<2) // help 
    {
       printhelp();
    }     

    string stropt;
    if(argc>1)  
    {
        stropt = string(argv[1]);
    }
    
     
        
    string pubkey;
    if(stropt==string("getnewaddress") ) 
    {
       string addr = getnewaddress("", pubkey);
       cout<<"get new address addr=  "<<addr << " pubkey  " << pubkey<<endl;
    } 
    else if(stropt==string("dumpwallet") ) 
    {
       string  strWalletFile(argv[2]);
       dumpwallet(strWalletFile);
       cout<<"dump wallet   "<<strWalletFile <<endl;
    } 
    else if(stropt==string("dumpprivkey") ) 
    {
       string  straddr(argv[2]);
       string privkey= dumpprivkey(straddr,pubkey);
       cout<<"dump privkey  "<<straddr<<" priv key "  << privkey  <<"  pub key  "<< pubkey   <<endl;
    }   
    else if(stropt==string("importprivkey") )
    {
       string  strkey(argv[2]);
       string  addr;
       bool bret= importprivkey(strkey ,addr);
       cout<<"import privkey  " << strkey  <<"  addr  "<< addr   <<endl;
    }
    else if(stropt==string("importwallet") ) 
    {
      string  strWalletFile(argv[2]);
      importwallet(strWalletFile);
       cout<<"import wallet  "<<strWalletFile <<endl;
    } 
    else 
    {
       printhelp();
    } 
   
    exitwallet();
   
   system("pause");


   return 0 ;

   CLoopBuf * sendbuf =new CLoopBuf;
   CLoopBuf * recvbuf  = new CLoopBuf;

   sendbuf->Init(6553600 , "walletsend_buf",1 ,1 );
   recvbuf->Init(6553600 , "walletrecv_buf",1 ,1 );
  
   WALLET_PDU * pPdu = new  WALLET_PDU;    
   int   nPduBufSize = sizeof(WALLET_PDU);
   while(1) 
   {
        recvbuf->PopOut((unsigned  char* )pPdu,nPduBufSize);
         
        sendbuf->PushIn((unsigned char*)pPdu, nPduBufSize);
   }

    
   char szBuf[128];
   return 0;
}
