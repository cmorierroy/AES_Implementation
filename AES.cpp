//Cedric Morier-Roy
//7689438
//COMP 4140

#include <iostream>
#include <string>
#include <sstream>
#include <iomanip>
#include <fstream>

using namespace std;

unsigned char sBox[256];
unsigned char invSBox[256];

//table of all 256 bit values multiplied by 02 in GF(2^8)
unsigned char mixColMult2[256];
unsigned char mixColMult3[256];
//Inverse look-up tables for all 256 bit values multiplied by 9,11,13,14 in GF(2^8)
unsigned char mixColMult9[256];
unsigned char mixColMult11[256];
unsigned char mixColMult13[256];
unsigned char mixColMult14[256];

//values for rCon
unsigned char round_constant[10] = {0x01, 0x02, 0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36};
    //taken from https://en.wikipedia.org/wiki/Rijndael_key_schedule

void createMixColTables()
{
    //CREATE MIXCOLUMNS TABLES
    //multiplication by 02 and 03
    for(unsigned int i = 0; i <= 255; i++)
    {
        mixColMult2[i] = (unsigned char)i << 1;
        if(i > 127)
        {
            mixColMult2[i] = mixColMult2[i] ^ 0x1b;
        }

        //create mixColMult3 table
        mixColMult3[i] = mixColMult2[i] ^ i;
    }

    unsigned char tmp1; //required for iterative 02 multiplication
    unsigned char tmp2; // ''
    //create mixColMult9 table
    for(unsigned int i = 0; i <= 255; i++)
    {
        tmp1 = i;
        for(int j = 0; j < 3; j++)
        {
            tmp2 = tmp1;
            tmp1 = (unsigned char)tmp1 << 1;
            if(tmp2 > 127)
            {
                tmp1 ^= 0x1b;
            }
        }
        tmp1 ^= i;
        mixColMult9[i] = tmp1;
    }

    //Create mixColMult11
    tmp1 = 0;
    tmp2 = 0;
    for(unsigned int i = 0; i <= 255; i++)
    {
        tmp1 = i;
        for(int j = 0; j < 3; j++)
        {
            tmp2 = tmp1;
            tmp1 = (unsigned char)tmp1 << 1;
            if(tmp2 > 127)
            {
                tmp1 ^= 0x1b;
            }
            if(j == 1)
            {
                tmp1 ^= i;
            }
        }
        tmp1 ^= i;
        mixColMult11[i] = tmp1;
    }

    //Create mixColMult13
    tmp1 = 0;
    tmp2 = 0;
    for(unsigned int i = 0; i <= 255; i++)
    {
        tmp1 = i;
        for(int j = 0; j < 3; j++)
        {
            tmp2 = tmp1;
            tmp1 = (unsigned char)tmp1 << 1;
            if(tmp2 > 127)
            {
                tmp1 ^= 0x1b;
            }
            if(j == 0)
            {
                tmp1 ^= i;
            }
        }
        tmp1 ^= i;
        mixColMult13[i] = tmp1;
    }

    //Create mixColMult14
    tmp1 = 0;
    tmp2 = 0;
    for(unsigned int i = 0; i <= 255; i++)
    {
        tmp1 = i;
        for(int j = 0; j < 3; j++)
        {
            tmp2 = tmp1;
            tmp1 = (unsigned char)tmp1 << 1;
            if(tmp2 > 127)
            {
                tmp1 ^= 0x1b;
            }
            if(j == 0 || j == 1)
            {
                tmp1 ^= i;
            }
        }
        mixColMult14[i] = tmp1;
    }
}

void rotWord(unsigned char* word)
{
    unsigned char temp;
    temp = word[0];
    word[0] = word[1];
    word[1] = word[2];
    word[2] = word[3];
    word[3] = temp;
}

void subWord(unsigned char* word)
{
    word[0] = sBox[word[0]];
    word[1] = sBox[word[1]];
    word[2] = sBox[word[2]];
    word[3] = sBox[word[3]];
}

void rCon(unsigned char* word, int i)
{
    word[0] ^= round_constant[i]; 
}

void KeyExpansion(unsigned char* key, unsigned char* expKey)
{
    int numBytes = 0; // keep track of how many bytes have been generated
    int rConNum = 0; //iteration for rCon
    unsigned char temp[4];

    //Copy key into first 16 bytes of schedule
    for(int i = 0; i < 16; i++)
    {
        expKey[i] = key[i];
        numBytes++;
    }

    //while we haven't generated all bytes of expanded key
    while(numBytes < 176)
    {
        //Read last 4 bytes of key
        for(int i = 0; i < 4; i++)
        {
            temp[i] = expKey[i + numBytes - 4];
        }

        //if we've generated 16 bytes, perform operations again
        if(numBytes % 16 == 0)
        {
            rotWord(temp);
            subWord(temp);
            rCon(temp, rConNum++);
        }

        //copy over new bytes in expanded key
        for(int i = 0; i < 4; i++)
        {
            expKey[numBytes] = expKey[numBytes - 16] ^ temp[i];
            numBytes++;   
        }
    }

    //Output key schedule
    cout << "Key Schedule:\n";
    for(int i = 0; i < 176; i++)
    {
        cout << setw(2) << setfill('0') << hex << (int) expKey[i];
        if((i+1)%4 == 0 && (i+1) % 16 != 0)
        {
            cout << ",";
        }
        if((i+1) % 16 == 0)
        {
            cout << "\n";
        }
    }
}

void SubBytes(unsigned char* state)
{
    //substitute state bytes with corresponding S-Box bytes
    for(int i = 0; i < 16; i++)
    {
        state[i] = sBox[state[i]];
    }
}

void ShiftRows(unsigned char* state)
{
    //Shift rows according to specified transformation
    unsigned char result[16];

    result[0] = state[0];
    result[1] = state[5];
    result[2] = state[10];
    result[3] = state[15];

    result[4] = state[4];
    result[5] = state[9];
    result[6] = state[14];
    result[7] = state[3];

    result[8] = state[8];
    result[9] = state[13];
    result[10] = state[2];
    result[11] = state[7];

    result[12] = state[12];
    result[13] = state[1];
    result[14] = state[6];
    result[15] = state[11];

    //copy over into state
    for(int i = 0; i < 16; i++)
    {
        state[i] = result[i];
    }
}

void MixColumns(unsigned char* state)
{
    unsigned char result[16];

    //column 1
    result[0] = mixColMult2[state[0]] ^ mixColMult3[state[1]] ^ state[2] ^ state[3];
    result[1] = state[0] ^ mixColMult2[state[1]] ^ mixColMult3[state[2]] ^ state[3];
    result[2] = state[0] ^ state[1] ^ mixColMult2[state[2]] ^ mixColMult3[state[3]];
    result[3] = mixColMult3[state[0]] ^ state[1] ^ state[2] ^ mixColMult2[state[3]];

    //column 2
    result[4] = mixColMult2[state[4]] ^ mixColMult3[state[5]] ^ state[6] ^ state[7];
    result[5] = state[4] ^ mixColMult2[state[5]] ^ mixColMult3[state[6]] ^ state[7];
    result[6] = state[4] ^ state[5] ^ mixColMult2[state[6]] ^ mixColMult3[state[7]];
    result[7] = mixColMult3[state[4]] ^ state[5] ^ state[6] ^ mixColMult2[state[7]];

    //column 3
    result[8] = mixColMult2[state[8]] ^ mixColMult3[state[9]] ^ state[10] ^ state[11];
    result[9] = state[8] ^ mixColMult2[state[9]] ^ mixColMult3[state[10]] ^ state[11];
    result[10] = state[8] ^ state[9] ^ mixColMult2[state[10]] ^ mixColMult3[state[11]];
    result[11] = mixColMult3[state[8]] ^ state[9] ^ state[10] ^ mixColMult2[state[11]];

    //column 4
    result[12] = mixColMult2[state[12]] ^ mixColMult3[state[13]] ^ state[14] ^ state[15];
    result[13] = state[12] ^ mixColMult2[state[13]] ^ mixColMult3[state[14]] ^ state[15];
    result[14] = state[12] ^ state[13] ^ mixColMult2[state[14]] ^ mixColMult3[state[15]];
    result[15] = mixColMult3[state[12]] ^ state[13] ^ state[14] ^ mixColMult2[state[15]];

    //copy back into state
    for(int i = 0; i < 16; i++)
    {
        state[i] = result[i];
    }
}

void AddRoundKey(unsigned char* state, unsigned char* roundKey)
{
    //xor roundkey bytes with state bytes
    for(int i = 0; i < 16; i++)
    {
        state[i] = roundKey[i] ^ state[i];
    }
}

void invShiftRows(unsigned char* state)
{
    //perform inverse shift row operation
    unsigned char result[16];
    
    result[0] = state[0];
    result[1] = state[13];
    result[2] = state[10];
    result[3] = state[7];

    result[4] = state[4];
    result[5] = state[1];
    result[6] = state[14];
    result[7] = state[11];

    result[8] = state[8];
    result[9] = state[5];
    result[10] = state[2];
    result[11] = state[15];

    result[12] = state[12];
    result[13] = state[9];
    result[14] = state[6];
    result[15] = state[3]; 

    //copy over into state
    for(int i = 0; i < 16; i++)
    {
        state[i] = result[i];
    }    
}

void invSubBytes(unsigned char* state)
{
    //copy corresponding bytes of inverse S-Box into state
    for(int i = 0; i < 16; i++)
    {
        state[i] = invSBox[state[i]];
    }
}

void invMixColumns(unsigned char* state)
{
    unsigned char result[16];

    //column 1
    result[0] = mixColMult14[state[0]] ^ mixColMult11[state[1]] ^ mixColMult13[state[2]] ^ mixColMult9[state[3]];
    result[1] = mixColMult9[state[0]] ^ mixColMult14[state[1]] ^ mixColMult11[state[2]] ^ mixColMult13[state[3]];
    result[2] = mixColMult13[state[0]] ^ mixColMult9[state[1]] ^ mixColMult14[state[2]] ^ mixColMult11[state[3]];
    result[3] = mixColMult11[state[0]] ^ mixColMult13[state[1]] ^ mixColMult9[state[2]] ^ mixColMult14[state[3]];

    //column 2
    result[4] = mixColMult14[state[4]] ^ mixColMult11[state[5]] ^ mixColMult13[state[6]] ^ mixColMult9[state[7]];
    result[5] = mixColMult9[state[4]] ^ mixColMult14[state[5]] ^ mixColMult11[state[6]] ^ mixColMult13[state[7]];
    result[6] = mixColMult13[state[4]] ^ mixColMult9[state[5]] ^ mixColMult14[state[6]] ^ mixColMult11[state[7]];
    result[7] = mixColMult11[state[4]] ^ mixColMult13[state[5]] ^ mixColMult9[state[6]] ^ mixColMult14[state[7]];

    //column 3
    result[8] = mixColMult14[state[8]] ^ mixColMult11[state[9]] ^ mixColMult13[state[10]] ^ mixColMult9[state[11]];
    result[9] = mixColMult9[state[8]] ^ mixColMult14[state[9]] ^ mixColMult11[state[10]] ^ mixColMult13[state[11]];
    result[10] = mixColMult13[state[8]] ^ mixColMult9[state[9]] ^ mixColMult14[state[10]] ^ mixColMult11[state[11]];
    result[11] = mixColMult11[state[8]] ^ mixColMult13[state[9]] ^ mixColMult9[state[10]] ^ mixColMult14[state[11]];

    //column 4
    result[12] = mixColMult14[state[12]] ^ mixColMult11[state[13]] ^ mixColMult13[state[14]] ^ mixColMult9[state[15]];
    result[13] = mixColMult9[state[12]] ^ mixColMult14[state[13]] ^ mixColMult11[state[14]] ^ mixColMult13[state[15]];
    result[14] = mixColMult13[state[12]] ^ mixColMult9[state[13]] ^ mixColMult14[state[14]] ^ mixColMult11[state[15]];
    result[15] = mixColMult11[state[12]] ^ mixColMult13[state[13]] ^ mixColMult9[state[14]] ^ mixColMult14[state[15]];

    //copy back into state
    for(int i = 0; i < 16; i++)
    {
        state[i] = result[i];
    }
}

void encrypt(unsigned char* plaintext, unsigned char* key)
{
    cout << "\nENCRYPTION PROCESS\n------------------\n"; 
    cout << "Plain Text:\n";

    unsigned char state[16];    //this will hold the state

    //copy plaintext to state
    for(int i = 0; i < 16; i++)
    {
        state[i] = plaintext[i];
        cout << setw(2) << setfill('0') << hex << (int) plaintext[i] << "  "; //output plaintext
        if((i+1) % 4 == 0)
        {
            cout << "     ";
        }
    }

    //specify 9 rounds (aside from initial and final rounds)
    int numRounds = 9;

    AddRoundKey(state, key);

    //Iterate over rounds
    for(int i = 0; i < numRounds;i++)
    {
        //Output progress
        cout << "\n\nRound " << (int)i+1 <<"\n---------\n";
        for(int j = 0; j < 16; j++)
        {
            cout << setw(2) << setfill('0') << hex << (int) state[j] << "  "; //output round
            if((j+1) % 4 == 0)
            {
                cout << "     ";
            }
        }

        //Perform round operations
        SubBytes(state);
        ShiftRows(state);
        MixColumns(state);
        AddRoundKey(state, key + (16 * (i + 1)));
    }

    //Last Round
    cout << "\n\nLast Round\n-----------\n";
    for(int i = 0; i < 16; i++)
    {
        cout << setw(2) << setfill('0') << hex << (int) state[i] << "  "; //output round
        if((i+1) % 4 == 0)
        {
            cout << "     ";
        }
    }

    SubBytes(state);
    ShiftRows(state);
    AddRoundKey(state,key + 160);

    //Save ciphertext over plaintext
    cout << "\n\nCiphertext:\n";
    for(int i = 0; i < 16; i++)
    {
        plaintext[i] = state[i];
        cout << setw(2) << setfill('0') << hex << (int) plaintext[i] << "  ";
        if((i+1) % 4 == 0)
        {
            cout << "     ";
        }
    }
    cout << endl;
}

void decrypt(unsigned char* ciphertext, unsigned char* key)
{
    cout << "\nDECRYPTION PROCESS\n------------------\n"; 
    cout << "CipherText:\n";

    unsigned char state[16];

    //copy ciphertext to state
    for(int i = 0; i < 16; i++)
    {
        state[i] = ciphertext[i];
        cout << setw(2) << setfill('0') << hex << (int) ciphertext[i] << "  "; //output ciphertext
        if((i+1) % 4 == 0)
        {
            cout << "     ";
        }
    }

    //Specify number of rounds (not including initial and final round)
    int numRounds = 9;

    AddRoundKey(state, key + 160);

    for(int i = numRounds; i > 0; i--)
    {
        //Output progress & perform round operations
        cout << "\n\nRound " << (int)i <<"\n---------\n";

        invShiftRows(state);
        invSubBytes(state);

        for(int j = 0; j < 16; j++)
        {
            cout << setw(2) << setfill('0') << hex << (int) state[j] << "  ";
            if((j+1) % 4 == 0)
            {
                cout << "     ";
            }
        }

        //Perform round operations
        AddRoundKey(state, key + (16 * i));
        invMixColumns(state);
    }

    invShiftRows(state);
    invSubBytes(state);

    //Last Round
    cout << "\n\nRound 0\n---------\n";
    for(int i = 0; i < 16; i++)
    {
        cout << setw(2) << setfill('0') << hex << (int) state[i] << "  ";
        if((i+1) % 4 == 0)
        {
            cout << "     ";
        }
    }

    AddRoundKey(state,key);

    //Save ciphertext over plaintext
    cout << "\n\nPlaintext:\n";
    for(int i = 0; i < 16; i++)
    {
        ciphertext[i] = state[i];
        cout << setw(2) << setfill('0') << hex << (int) ciphertext[i] << "  ";
        if((i+1) % 4 == 0)
        {
            cout << "     ";
        }
    }
    cout << endl;
}

int main(int argc, char *argv[])
{
    cout << "*****BEGINNING PROGRAM*****" << "\n\n";

    //Obtain filename arguments
    std::string mFilename(argv[1]);
    std::string kFilename(argv[2]);
    std::string sBoxFilename(argv[3]);
    std::string invSBoxFilename(argv[4]);

    //Print filenames:
    cout << "Plaintext filename: " << mFilename << "\n";
    cout << "Key filename: " << kFilename << "\n";
    cout << "S-Box filename: " << sBoxFilename << "\n";
    cout << "Inverse S-Box filename: " << invSBoxFilename << "\n";
    cout << "\n";

    //KEY READING
    ifstream kFile(kFilename);
    unsigned int temp;
    char hexVal[3];
    unsigned char key[16];
    int inc = 0;

    //READ THROUGH KEY FILE
    while(!kFile.eof())
    {
        if(inc < 16)
        {
            kFile >> hexVal[0];
            kFile >> hexVal[1];
            std::istringstream converter(hexVal);
            converter >> std::hex >> temp;
            key[inc++] = temp;
        }
        else
        {
            //get last character of file
            kFile >> hexVal[0];
        }
    }
    kFile.close();

    //READ SBOX
    ifstream sBoxFile(sBoxFilename);
    temp = 0;
    inc = 0;

    while(inc < 256)
    {
        sBoxFile >> hexVal[0];
        sBoxFile >> hexVal[1];
        std::istringstream converter(hexVal);
        converter >> std::hex >> temp;
        sBox[inc++] = temp;
    }
    sBoxFile.close();

    //READ INVERSE S-BOX
    ifstream invSBoxFile(invSBoxFilename);
    temp = 0;
    inc = 0;

    while(inc < 256)
    {
        invSBoxFile >> hexVal[0];
        invSBoxFile >> hexVal[1];
        std::istringstream converter(hexVal);
        converter >> std::hex >> temp;
        invSBox[inc++] = temp;
    }
    invSBoxFile.close();

    //READ PLAINTEXT
    ifstream mFile(mFilename);
    temp = 0;
    unsigned char block [16];
    inc = 0;

    while(inc < 16)
    {
        mFile >> hexVal[0];
        mFile >> hexVal[1];
        std::istringstream converter(hexVal);
        converter >> std::hex >> temp;
        block[inc++] = temp;
    }
    mFile.close();

    //Create lookup tables for mixColumn and inverse mixColumn operations
    createMixColTables();
    
    //Key Expansion
    unsigned char expKey[176];
    KeyExpansion(key, expKey);

    //Encryption
    encrypt(block, expKey);
    cout << endl;

    //Decryption
    decrypt(block, expKey);
    
    cout << "\nEnd of processing.\n";
    return 0;
}