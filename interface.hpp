#pragma once

#include <iostream>
#include <string>
#include <cstring>
#include <vector>
#include <shuffle/Utils.h>

#include <sodium.h>
#include <sodiumwrap/sodiumtester.h>
#include <sodiumwrap/box_seal.h>
#include <sodiumwrap/keypair.h>
#include <sodiumwrap/allocator.h>
#include <sodiumwrap/secretbox.h>

#include <shuffle/CipherTable.h>
#include <shuffle/Globals.h>
#include <shuffle/Functions.h>

#include <string.h>
#include <shuffle/RemoteShuffler.h>
#include <shuffle/FakeZZ.h>
#include <shuffle/SchnorrProof.h>

using namespace std;
using namespace sodium;

#define CIPHERTEXT_SIZE CURVE_POINT_BYTESIZE*2

inline void g_encrypt(char* secrets, int secretlen, int keyindex,
        string &ciphers, vector<string> &groupelts, int*elem_size){
   int num_sercrets = strlen(secrets) / secretlen;

   char** cargs = makeCharArray(num_sercrets);

   int src_index = 0;
   int i;
   for(i = 0; i < num_sercrets; i++){
       setArrayString(cargs, secrets, i, src_index, secretlen);
       src_index = src_index + secretlen;
   }

   auto ptr = &cargs;
   CipherTable* cCipher = (CipherTable*) encrypt((void**) cargs, secretlen, num_sercrets, keyindex);

   int clen;
   int element_size;
   char* cCipherStr = (char*) get_ciphertexts(cCipher, &clen, &element_size);
   string cipherstr(cCipherStr);

   delete_str(cCipherStr);

   int num_elements_post_enc = clen / element_size;
   vector<string> elements;
   int j;
   for(j = 0; j < num_elements_post_enc; j++){
       char* elem = (char*) get_element(cCipher, j, &clen);
       elements.push_back(string(elem));
   }
   delete_ciphers(cCipher);
   freeCharArray(cargs, num_sercrets);
   ciphers = cipherstr;
   groupelts = elements;
   elem_size = &element_size;
}

 
inline void g_decrypt(string all_cipher_text, int keyindex, vector<string> &groupelts){
    ElGammal* elgammal = (ElGammal*) create_decryption_key(keyindex);

    CipherTable* ciphertable = (CipherTable*) parse_ciphers(&all_cipher_text[0],
            all_cipher_text.size(), elgammal);

    int rows = ciphertable->rows();
    int cols = ciphertable->cols();
    int num_of_ciphers = rows * cols;

    string arr[num_of_ciphers];
    cout << "HERE 1" << endl;

    int i; int j;
    for(i = 0; i < rows; i++){
        for(j = 0; j < cols; j++){
            int* clen;
            char* ptx = (char*) decrypt_cipher(ciphertable, i, j, &clen, elgammal);
            printf("%s",ptx);
            printf("\n");
            arr[i*cols+j] = string(ptx);
            delete_str(ptx);
        }
    }
    delete_ciphers(ciphertable);
    for(auto x : arr){
        groupelts.push_back(x);
    }
    free(elgammal);
}

class Groth{
    public:
        void Encrypt(char *secrets, int secretlen, int keyindex,
            string &ciphersR, vector<string> &groupelts, int *elemsize);
        void Decrypt(string ciphers,  int keyindex,
                vector<string> &groupelts);
std::tuple<vector<string>, vector<secretbox<>::nonce_type>, string>
        Wrap(vector<string> msgs, int msgsize, int keyindex);
        
        vector<string> UnWrap(std::tuple<vector<string>,
        vector<secretbox<>::nonce_type>, string> ctxs_nonces_ciphers, int keyindex);
        void Test();
        void Test2();
};

std::tuple<vector<string>, vector<secretbox<>::nonce_type>, string>
Groth::Wrap(vector<string> msgs, int msgsize, int keyindex){
    int n = msgs.size() / msgsize;
   // int osize = msgsize + (CURVE_POINT_BYTESIZE * 2);
    //char wrapped[n * osize];

    char seeds[n * 32];
    for(int i = 0; i < strlen(seeds); i++){
        seeds[i] = (char)rand();
    }
    
    //char arr[32];
    string ciphersR;
    vector<string> groupelts;
    vector<string> wrapped;
    vector<secretbox<>::nonce_type> nonces;
   // vector<string> decgroup;
    int* elem;
    this->Encrypt(seeds, 32, keyindex, ciphersR, groupelts, elem);
    //int i = 0;
    for(int i = 0; i < n; i++){
        cout << "I = " << i << endl;
        std::string enctmp = msgs[i];
        bytes tmpenc{enctmp.cbegin(), enctmp.cend()};

        //std::string tmpip = mixers[i].first;
        unsigned char out[crypto_hash_sha256_BYTES];
        auto rez = reinterpret_cast<unsigned char*>(const_cast<char*>(groupelts[i].c_str()));
        crypto_hash_sha256(out, rez, sizeof(rez)/sizeof(rez[0]));
        //TODO: Stop using sodiumwarp and just use libsodium raw
        bytes_protected key;
        for(auto x : out){
            key.push_back(x);
        }
        cout << "KEY = " << sizeof(out)/sizeof(out[0]) << endl;
        secretbox<>::key_type keyty;
        cout << "OG KEY = " << keyty.keydata_.size() << endl;
        keyty.keydata_.clear();
        keyty.keydata_.insert(keyty.keydata_.end(), key.begin(), key.end());
        secretbox<> sc(keyty);
        secretbox<>::nonce_type nonce{};
        tmpenc = sc.encrypt(tmpenc, nonce);
      
        std::string tt{tmpenc.cbegin(), tmpenc.cend()};
        //tt += tmpip;   // Address
        //tt += "CUTHERE";
        //tt += std::to_string(tmpip.size()); // Size of ip address

        wrapped.push_back(tt); 
        nonces.push_back(nonce);
        //i++;
    }
    cout << "DEBUG: MADE IT WRAP DONE" << endl;
    return std::make_tuple(wrapped, nonces, ciphersR);
}

vector<string> Groth::UnWrap(std::tuple<vector<string>,
        vector<secretbox<>::nonce_type>, string> ctxs_nonces_ciphers, int keyindex){
    vector<string> decgroup;
    vector<string> plaintext;
    this->Decrypt(std::get<2>(ctxs_nonces_ciphers), keyindex, decgroup);

    for(int i = 0; i < std::get<0>(ctxs_nonces_ciphers).size(); i++){
        bytes tmpdec{std::get<0>(ctxs_nonces_ciphers)[i].cbegin(),
            std::get<0>(ctxs_nonces_ciphers)[i].cend()};

        unsigned char out[crypto_hash_sha256_BYTES];
        auto rez = reinterpret_cast<unsigned char*>(const_cast<char*>(decgroup[i].c_str()));
        crypto_hash_sha256(out, rez, sizeof(rez)/sizeof(rez[0]));

        bytes_protected key;
        for(auto x : out){
            key.push_back(x);
        }
        secretbox<>::key_type keyty;
        keyty.keydata_ = key;
        secretbox<> sc(keyty);

        tmpdec = sc.decrypt(tmpdec, std::get<1>(ctxs_nonces_ciphers)[i]);
      
        std::string tt{tmpdec.cbegin(), tmpdec.cend()};
        
        plaintext.push_back(tt);
    }
    cout << "DEBUG: MADE IT UNWRAP DONE" << endl;
    return plaintext;
}

void Groth::Encrypt(char *secrets, int secretlen, int keyindex,
        string &ciphersR, vector<string> &groupelts,  int *elemsize){
    g_encrypt(secrets, secretlen, keyindex, ciphersR, groupelts, elemsize);
}

void Groth::Decrypt(string ciphers, int keyindex, vector<string> &groupelts){
   g_decrypt(ciphers, keyindex, groupelts); 
}

void Groth::Test(){
    init();
   char arr[32];
   for(int i = 0; i < 32; i++){
       arr[i] = 'b';
   }
   string ciphersR;
   vector<string> groupelts;
   vector<string> decgroup;
   int* elem;
   this->Encrypt(arr, 32, 1, ciphersR, groupelts, elem);
   for(auto x : groupelts){
       cout << x << endl;
   }
   cout << "BREAK BREAK BREAK BREAK BREAK " << endl;
  this->Decrypt(ciphersR, 1, decgroup);
  for(auto x : decgroup){
    cout << x << endl;
  }
  cout << "MADE IT HERE" << endl;
}

void Groth::Test2(){
    sodium_init();
    string msg = "test";
    vector<string> msgs;
    for(int i = 0; i < 30; i++){
        msgs.push_back(msg);
    }
    auto rez = Wrap(msgs, msg.length(), 1);
    auto rez2 = UnWrap(rez, 1);
    for(auto x : rez2){
        cout << x << endl;
    }
}
