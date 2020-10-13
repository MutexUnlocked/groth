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
#define MESSAGE_LEN 32
#define CIPHTERTEXT_LEN (MESSAGE_LEN + crypto_secretbox_MACBYTES)

inline string uchar_arr_to_string(unsigned char* arr){
   return  std::string(reinterpret_cast<char*>(arr));
}

inline unsigned char* string_to_uchar_arr(string str){
    unsigned char* arr = (unsigned char*) malloc(sizeof(char) * str.length());
    for(int i = 0; i < str.length(); i++){
        arr[i] = str[i];
    }
    return arr;
}

inline void g_shuffle(char* ciphers, int num_of_elements, int keyindex,
        void *cached_shuffle, char* shuffled_ciphers, int* permutation){
    auto elgammal = create_pub_key(keyindex);
    
	int shuffled_ciphers_len;
	int permutation_len;

    cached_shuffle = shuffle_internal(elgammal, ciphers, strlen(ciphers),num_of_elements ,&shuffled_ciphers, 
            &shuffled_ciphers_len, &permutation, &permutation_len);


    delete_key(elgammal);
}

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
std::tuple<vector<string>, vector<string>, string>
        Wrap(vector<string> msgs, int msgsize, int keyindex);
        
        vector<string> UnWrap(std::tuple<vector<string>,
        vector<string>, string> ctxs_nonces_ciphers, int keyindex);
        void Test();
        void Test2();
};

std::pair<char*, int*> Shuffle(string ciphers, int keyindex){
    char* shuffled_ciphers;
    char* cached_shuffle;
    int* perm;

    ElGammal* elgammal = (ElGammal*) create_pub_key(keyindex);
    
    CipherTable* ciphertable = (CipherTable*) parse_ciphers(&ciphers[0],
            ciphers.size(), elgammal);

    int rows = ciphertable->rows();
    int cols = ciphertable->cols();
    int num_of_ciphers = rows * cols;

    string arr[num_of_ciphers];
    g_shuffle(&ciphers[0], num_of_ciphers, keyindex, cached_shuffle, shuffled_ciphers, perm);
    return std::make_pair(shuffled_ciphers, perm);

}
std::tuple<vector<string>, vector<string>, string>
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
    vector<string> nonces;
   // vector<string> decgroup;
    int* elem;
    this->Encrypt(seeds, 32, keyindex, ciphersR, groupelts, elem);
    //int i = 0;
    for(int i = 0; i < n; i++){
        cout << "I = " << i << endl;
   
        unsigned char out[crypto_hash_sha256_BYTES];
        unsigned char nonce[crypto_secretbox_NONCEBYTES];
        unsigned char ciphertext[CIPHTERTEXT_LEN];
        auto rez = reinterpret_cast<unsigned char*>(const_cast<char*>(groupelts[i].c_str()));
        crypto_hash_sha256(out, rez, sizeof(rez)/sizeof(rez[0]));

        randombytes_buf(nonce, sizeof(nonce));
        crypto_secretbox_easy(ciphertext, string_to_uchar_arr(msgs[i]), MESSAGE_LEN, nonce, out);
        wrapped.push_back(uchar_arr_to_string(ciphertext)); 
        nonces.push_back(uchar_arr_to_string(nonce));
        
    }
    cout << "DEBUG: MADE IT WRAP DONE" << endl;
    return std::make_tuple(wrapped, nonces, ciphersR);
}

vector<string> Groth::UnWrap(std::tuple<vector<string>,
          vector<string>, string> ctxs_nonces_ciphers, int keyindex){
    vector<string> decgroup;
    vector<string> plaintext;
     this->Decrypt(std::get<2>(ctxs_nonces_ciphers), keyindex, decgroup);

    for(int i = 0; i < std::get<0>(ctxs_nonces_ciphers).size(); i++){
        string tmpdec = std::get<0>(ctxs_nonces_ciphers)[i];

        unsigned char out[crypto_hash_sha256_BYTES];
        auto rez = reinterpret_cast<unsigned char*>(const_cast<char*>(decgroup[i].c_str()));
        crypto_hash_sha256(out, rez, sizeof(rez)/sizeof(rez[0]));
        unsigned char* nonce = string_to_uchar_arr(std::get<1>(ctxs_nonces_ciphers)[i]);
        unsigned char decrypted[MESSAGE_LEN];

        crypto_secretbox_open_easy(decrypted, string_to_uchar_arr(tmpdec),CIPHTERTEXT_LEN, nonce, out);
        
        plaintext.push_back(uchar_arr_to_string(decrypted));
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
