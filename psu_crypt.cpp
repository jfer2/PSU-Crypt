#include <iostream>
#include <fstream>
#include <string> 
#include <bitset> 
#include "ftable.h"
#include <sstream>
#include <math.h>
#include <iomanip>

using namespace std;

void make_80_bit_key(string str_key);
void make_subkeys(int encryption);
void circular_left_shift(void);
unsigned int K(int x);
string get_key(char * file_path);
void encrypt_plaintext_file(string file_path); 
void decrypt_ciphertext_file(void);
void partition_block(string block);
void parse_ciphertext_block(string s);
void whitening_step(void);
void output_whitening(void);
void output_ciphertext(void);
void output_decrypted_ciphertext(void);
void F_func(bitset<16> R_0, bitset<16> R_1, int round);
bitset<16> g_perm(bitset<16> w, int round);
bitset<8> ftable_lookup(bitset<8> bst);
bitset<16> concat_to_16(bitset<8> high, bitset<8> low);


const int ROUNDS = 20;
int ROUND = 0;
unsigned int ESK [ROUNDS][12];
unsigned int DSK [ROUNDS][12];
int KEY_DEX = 0;
bitset<80> KEY;
bitset<16> W[4];
bitset<16> R[4];
bitset<16> C[4];
bitset<16> F[2];

int main(int argc, char ** argv)
{
    string str_key = get_key(argv[1]);
    make_80_bit_key(str_key);
    make_subkeys(0);
    //encrypt_plaintext_file(argv[2]);
    
    /*for (int i = 0; i < ROUNDS; ++i)
    {
        for (int j = 0; j < 12; ++j)
            cout << hex << ESK[i][j] << " ";
        cout << endl;
    }*/
    decrypt_ciphertext_file();

    return 0;
}

void make_80_bit_key(string str_key)
{
    string temp = str_key.substr(0, 16);
    KEY = stoull(temp, nullptr, 16);
    KEY = KEY << 16;
    temp = str_key.substr(16, 4);
    bitset<16> bst_temp (stoull(temp, nullptr, 16));

    int j = 15;
    for (auto i : bst_temp.to_string())
    {
        KEY[j] = i - 48;
        --j;
    }
}

string get_key(char * file_path)
{
    string str_key;
    ifstream key_file(file_path);
    if (key_file.is_open())
        getline(key_file, str_key);
    else
    {
        cout << "\n\t-- Error opening file" << endl;
        exit(1);
    }
    key_file.close();
    return str_key;
}

void make_subkeys(int encryption)
{
    for (int i = 0; i < ROUNDS; ++i)
        for (int j = 0; j < 12; ++j)
        {
            unsigned int x = (4 * i) + (j % 4);
            ESK[i][j] = K(x);
        }

    int k = 19;
    if (!encryption)
    {
        for (int i = 0; i < ROUNDS; ++i)
        {
            for (int j = 0; j < 12; ++j)
            {
                DSK[i][j] = ESK[k][j];
            }
            --k;
        }
        for (int i = 0; i < ROUNDS; ++i)
        {
            for (int j = 0; j < 12; ++j)
                ESK[i][j] = DSK[i][j];
        }
    }
}

unsigned int K(int x)
{
    int get_byte = x % 10;
    int index = get_byte * 8;
    bitset<8> bst_byte;
    circular_left_shift();
    for (int i = 0; i < 8; ++i)
    {
        bst_byte[i] = KEY[index];
        ++index;
    }
    return (unsigned int) bst_byte.to_ulong();
}


void circular_left_shift(void)
{
    int last_bit = KEY[79];
    KEY = KEY << 1;
    KEY[0] = last_bit;
}


void parse_ciphertext_block(string s)
{
    for (int i = 0; i < 4; ++i)
    {
        string temp = s.substr(i * 4, 4);
        W[i] = stoull(temp, nullptr, 16);
    }
}

void output_decrypted_ciphertext(void)
{
    for (int j = 0; j < 4; ++j)
    {
        bitset<8> t1, t2;
        for (int i = 0; i < 8; ++i)
        {
            t1[i] = C[j][i+8];
            t2[i] = C[j][i];
        }
        //cout << "t1/t2 = " << hex << t1.to_ullong() << " " << t2.to_ullong() << endl;
        
        char x = t1.to_ullong();
        char y = t2.to_ullong();
        //cout << x << y;
        ofstream myfile;
        myfile.open("output/plaintext_after_dec.txt", ios::app);
        if (myfile.is_open())
        {
            myfile << x << y;
            myfile.close();
        }
    }
}

void decrypt_ciphertext_file(void)
{
    ifstream myfile("input/ciphertext.txt");
    string ciphertext_block;
    bool again = true;
    while (again)
    {
               
        if (myfile.is_open())
        {
            getline(myfile, ciphertext_block, '\n');
        }
        if (!myfile.eof())
        {
            parse_ciphertext_block(ciphertext_block);
            whitening_step();
            for (int i = 0; i < 20; ++i)
            {
                F_func(R[0], R[1], ROUND);
                bitset<16> temp;

                temp = R[0].to_ullong();
                R[0] = R[2] ^ F[0];
                R[2] = temp;

                temp = R[1].to_ullong();
                R[1] = R[3] ^ F[1];
                R[3] = temp;

                /*for (int j = 0; j < 4; ++j)
                  cout << hex << R[j].to_ullong();
                cout << endl;*/

                ++ROUND;
            }
            ROUND = 0;
            output_whitening();
            output_decrypted_ciphertext();
        }
        else
        {
            again = false;
        }
    }
}


void encrypt_plaintext_file(string file_path)
{
    int count = 0;
    char ch;
    int c;
    bool again = true;

    ifstream pt_file(file_path, fstream::in);

    if (pt_file.is_open())
    {
        while (again)
        {
            string block_64;

            c = pt_file.peek();
            if (c != EOF)
            {
                while( (c != EOF) && (count != 8) && (pt_file >> noskipws >> ch) )
                {
                    //cout << ch << " ";
                    block_64.append(1, ch);
                    ++count;
                    c = pt_file.peek();
                }
                if (c == EOF)
                {
                    again = false;
                    int padding = 8 - count + 1;
                    cout << "pad = " << padding << endl;
                    block_64.pop_back();
                    cout << "from inside padding block = block_64 = " << block_64.length() << endl;
                    for (int i = 0; i < padding; ++i)
                        block_64.append(1, '!');
                    cout << "from inside padding block = block_64 = " << block_64 << endl;
                }
                //cout << "block64 = " << block_64 << endl;
                //cout << "count = " << count << endl;
                //getline(pt_file, block_64);
                //pt_file.close();
                //cout << block_64.length() << endl;
                //
                cout << "block64= " << block_64 << endl;

                partition_block(block_64);
                whitening_step();
                for (int i = 0; i < 20; ++i)
                {
                    F_func(R[0], R[1], ROUND);
                    bitset<16> temp;

                    temp = R[0].to_ullong();
                    R[0] = R[2] ^ F[0];
                    R[2] = temp;

                    temp = R[1].to_ullong();
                    R[1] = R[3] ^ F[1];
                    R[3] = temp;
                    
                    /*for (int j = 0; j < 4; ++j)
                      cout << hex << R[j].to_ullong();
                    cout << endl;*/

                    ++ROUND;
                    count = 0;
        
                }
                output_whitening();
                output_ciphertext();
                ROUND = 0;
                    
                /*for (int i = 0; i < 4; ++i)
                   cout << hex << C[i].to_ullong() << " ";
                cout << endl;*/
            }
        }
    pt_file.close();
    }
}


void F_func(bitset<16> R_0, bitset<16> R_1, int round)
{
    bitset<16> temp;
    int r = round % 4;
    unsigned long long x = pow (2, 16);
    bitset<16> T0, T1;
    T0 = g_perm(R_0, round);
    T1 = g_perm(R_1, round);
    temp = concat_to_16(ESK[round][KEY_DEX], ESK[round][KEY_DEX+1]);
    F[0] = ( T0.to_ullong() + (2 * T1.to_ullong()) + temp.to_ullong() ) % x;
    temp = concat_to_16(ESK[round][KEY_DEX+2], ESK[round][KEY_DEX+3]);
    F[1] = ( (2 * T0.to_ullong()) + T1.to_ullong() + temp.to_ullong() ) % x;
    KEY_DEX = 0;
}

void output_ciphertext(void)
{
    ofstream myfile;
    myfile.open("output/ciphertext.txt", ios::app);
    if (myfile.is_open())
    {
        cout << hex << setw(4) << setfill('0') << C[0].to_ullong();
        cout << " ";
        cout << hex << setw(4) << setfill('0') << C[1].to_ullong();
        cout << " ";
        cout << hex << setw(4) << setfill('0') << C[2].to_ullong();
        cout << " ";
        cout << hex << setw(4) << setfill('0') << C[3].to_ullong();
        cout << endl;

        myfile << hex << setw(4) << setfill('0') << C[0].to_ullong();
        myfile << hex << setw(4) << setfill('0') << C[1].to_ullong();
        myfile << hex << setw(4) << setfill('0') << C[2].to_ullong();
        myfile << hex << setw(4) << setfill('0') << C[3].to_ullong();
        myfile << '\n';

        //myfile << hex << setw(4) << setfill('0') << C[0].to_ullong() << C[1].to_ullong() << C[2].to_ullong() << C[3].to_ullong() << '\n';
        myfile.close();
    }

}

bitset<16> concat_to_16(bitset<8> high, bitset<8> low)
{
    bitset<16> ret;
    for (int i = 0; i < 8; ++i)
        ret[i] = low[i];
    int j = 0;
    for (int i = 8; i < 16; ++i)
    {
        ret[i] = high[j];
        ++j;
    }
    return ret;
}

bitset<16> g_perm(bitset<16> w, int round)
{
    int r = round % 4;
    bitset<16> concat_g5_g6;
    bitset<8>g[7];
    bitset<8> temp;
    
    for (int i = 0; i < 8; ++i)
        g[2][i] = w[i];

    int j = 0;
    for (int i = 8; i < 16; ++i)
    {
        g[1][j] = w[i];
        ++j;
    }
    for (int i = 1; i < 5; ++i)
    {
        temp = ESK[r][KEY_DEX];
        temp = temp ^ g[i+1];
        temp = ftable_lookup(temp);
        g[i+2] = temp ^ g[i];
        ++KEY_DEX;
    }

    bitset<16> ret;
    for (int i = 0; i < 8; ++i)
        ret[i] = g[6][i];
    j = 0;
    for (int i = 8; i < 16; ++i)
    {
        ret[i] = g[5][j];
        ++j;
    }
    return ret;
}

bitset<8> ftable_lookup(bitset<8> bst)
{
    bitset<4> high, low;
    for (int i = 0; i < 4; ++i)
        low[i] = bst[i];
    int j = 0;
    for (int i = 4; i < 8; ++i)
    {
        high[j] = bst[i];
        ++j;
    }

    bitset<8> ret( ftable[16 * high.to_ullong() + low.to_ullong()] );
    return ret;
}

void partition_block(string block)
{
    int partition = 0;

    for (int i = 0; i < 4; ++i)
    {
        stringstream ss;
        int j = i * 2;
        string str_16_bit_hex;
        ss << hex << (int)block[j];
        ss << hex << (int)block[j + 1];
        ss >> str_16_bit_hex;
        W[i] = stoull(str_16_bit_hex, nullptr, 16);
    }
}

void output_whitening(void)
{
    bitset<16> bst_white[4];

    int k_dex = 79;
    int w_dex = 15;
    int count = 0;
    int i = 0;

    while (count < 64)
    {
        bst_white[i][w_dex] = KEY[k_dex];
        --w_dex;
        --k_dex;
        ++count;

        if (w_dex < 0)
        {
            w_dex = 15;
            ++i;
        }
    }
    C[0] = R[2] ^ bst_white[0];
    C[1] = R[3] ^ bst_white[1];
    C[2] = R[0] ^ bst_white[2];
    C[3] = R[1] ^ bst_white[3];
}

void whitening_step(void)
{
    // partition 80 bit key into four 16-bit keys for whitening 
    bitset<16> bst_white[4];

    int k_dex = 79;
    int w_dex = 15;
    int count = 0;
    int i = 0;

    while (count < 64)
    {
        bst_white[i][w_dex] = KEY[k_dex];
        --w_dex;
        --k_dex;
        ++count;

        if (w_dex < 0)
        {
            w_dex = 15;
            ++i;
        }
    }
    for (int i = 0; i < 4; ++i)
        R[i] = W[i] ^ bst_white[i];
}

