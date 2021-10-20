#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>
#include "int.h"
#include "event.h"
#include "cpu_hal.h"
#include "uart.h"
#include "bench.h"
#include "user_plugin/sha256.h"

#define IRQ_UP_IDX 22

// Must use volatile,
// because it is used to communicate between IRQ and main thread.
volatile int g_up_int_triggers = 0;

void ISR_UP() {
    // Clear interrupt within user plugin peripheral
    UP_APB_CMD = UP_CMD_CLR_INT_BIT;
    ICP = 1 << IRQ_UP_IDX;

    ++g_up_int_triggers;
    printf("In User Plugin interrupt\n");
}

//---------write process----------//
//write_word
void write_word(unsigned int address, int word){
    printf("address is 0x%x.\n",address);
    printf("message is 0x%08X.\n",word);
	SHA256_ADDRESS = address;
    SHA256_MESSAGE = word;
    SHA256_RW = 0x3 ;
    SHA256_RW = 0x0;	
}

unsigned int w[16];
//write_block
void write_block(){
    printf("write_block process starting here!!!\n");
    SHA256_RW = 0x0;	
    write_word(ADDR_BLOCK0, w[0]);
    write_word(ADDR_BLOCK1, w[1]);
    write_word(ADDR_BLOCK2, w[2]);
    write_word(ADDR_BLOCK3, w[3]);
    write_word(ADDR_BLOCK4, w[4]);
    write_word(ADDR_BLOCK5, w[5]);
    write_word(ADDR_BLOCK6, w[6]);
    write_word(ADDR_BLOCK7, w[7]);
    write_word(ADDR_BLOCK8, w[8]);
    write_word(ADDR_BLOCK9, w[9]);
    write_word(ADDR_BLOCK10, w[10]);
    write_word(ADDR_BLOCK11, w[11]);
    write_word(ADDR_BLOCK12, w[12]);
    write_word(ADDR_BLOCK13, w[13]);
    write_word(ADDR_BLOCK14, w[14]);
    write_word(ADDR_BLOCK15, w[15]);
    write_word(ADDR_CTRL, (CTRL_MODE_VALUE + CTRL_INIT_VALUE));
    printf("write_block process by finished here!!!\n");
}
//----------end write process----------//
int read_data;
//--------read digest process----------//
//read_word
void read_word(unsigned int address){
	SHA256_ADDRESS = address;
    SHA256_RW = 0x2;	
    read_data = SHA256_DIGEST;
    SHA256_RW = 0x0;	
}
//
//-------wait for generating digest----//
void wait_ready(){
    read_data = 0;
    while (read_data == 0){
        read_word(ADDR_STATUS);
        printf("read_data is 0x%08X .\n",read_data);
        printf("Waiting for hash calculated completely!!!<_>\n");
    }
}
//
unsigned int digest_data [8];
//read_digest
void read_digest(){
    printf("read_digest process starting here!!!\n");
    SHA256_RW = 0x0;	
    read_word(ADDR_DIGEST0);
    digest_data[0] = read_data;
    read_word(ADDR_DIGEST1);
    digest_data[1] = read_data;
    read_word(ADDR_DIGEST2);
    digest_data[2] = read_data;
    read_word(ADDR_DIGEST3);
    digest_data[3] = read_data;
    read_word(ADDR_DIGEST4);
    digest_data[4] = read_data;
    read_word(ADDR_DIGEST5);
    digest_data[5] = read_data;
    read_word(ADDR_DIGEST6);
    digest_data[6] = read_data;
    read_word(ADDR_DIGEST7);
    digest_data[7] = read_data;
    printf("read_digest process by finished here!!!\n");
}
//
void do_check_sha256(int* errors, int msg_num){

    unsigned expect_out [32] = {
                           //message0 "a"(0x61)'s expected output
                           0xCA978112, 0xCA1BBDCA, 0xFAC231B3, 0x9A23DC4D,
                           0xA786EFF8, 0x147C4E72, 0xB9807785, 0xAFEE48BB,                   
                           //message1 "aaabbbcccdddeeefff"(0x616161626262636363646464656565666666)'s expected output
                           0x5662CF7A, 0xB1070E44, 0x8A9D28B4, 0xD39C188E,
                           0xEBCC91B6, 0x6F309F9C, 0x415C24A8, 0x15C82A04,
                           
                           //message2 "hello world!"(0x68656c6c6f20776f726c6421)'s expected output
                           0x7509E5BD, 0xA0C762D2, 0xBAC7F90D, 0x758B5B22, 
                           0x63FA01CC, 0xBC542AB5, 0xE3DF163B, 0xE08E6CA9,
                           
                           //message3 "aaa...bbb...ccc...ddd"(0x61..62..63..64)'s expected output
                           0xEC5A7706, 0xDF5E6AE5, 0x46A6F192, 0x5BB4CE3F, 
                           0x62D62611, 0xD60AE851, 0xAABCD160, 0x8F99D23B, 
 
                           }; 


    unsigned int expect_msg = {
                          0x61000000, //message1: "a"
                         };

    //Read message and outputs
    if (msg_num == 0){
        unsigned int message = SHA256_MESSAGE;
        if(message != expect_msg){
           printf("MESSAGE WRONG! EXPECTED MESSAGE IS 0x%X, WRONG MESSAGE IS 0x%X",expect_msg,message);
        }
        else{
            printf("MESSAGE RIGHT! MESSAGE IS 0x%X \n",message);
        }
    }
    
    for(int i = 0; i < 8; i++ ){
        if( digest_data[i] != expect_out[i + msg_num * 8] ){
            ++errors;
            printf("EXPECTED OUTPUT IS 0x%X, WRONG OUTPUT IS 0x%X \n", expect_out[i + msg_num * 8], digest_data[i]);
        }

        else{
            printf("OUT RIGHT! OUT IS 0x%X \n", digest_data[i] );  
        }
    }
 
    printf("INTERRUPT NUM AT ALL IS %X\n",g_up_int_triggers );
}

//
void handle_message(const char *msg_in, size_t len){
    unsigned int r = (int)(len * 8 % 512);
    unsigned int append = ((r < 448) ? (448 - r) : (448 + 512 -r)) / 8;
    unsigned int new_len = len + append + 8; //original data+append+data_lenth
    unsigned char new_msg[new_len];
    bzero(new_msg+len,append);
    if(len > 0){
        memcpy(new_msg, msg_in, len);	 
    }
    new_msg[len] = (unsigned char)0x80;
    uint64_t bits_len = len * 8;
	printf("message's Dec_lenth is %u, Hex_lenth is 0x%X. \n",len * 8,len * 8);
    for (int i = 0; i < 8; i++){
        new_msg[len + append + i] = (bits_len >> ((7 - i) * 8)) & 0xff;
    } 
    bzero(w,16);
    unsigned int chunk_len = new_len / 64; //devide 512bit block
    printf("chunk_len is %d.\n",chunk_len);
    for (size_t idx = 0; idx < chunk_len; idx++){
        uint32_t val = 0;
        for (int i = 0; i < 64; i++){ //16 * 32bit big_endian, as w[0], ... w[15]
            val = val | (*(new_msg + idx * 64 + i) << (8 * (3 - i)));
            if(i % 4 == 3){
                w[i/4] = val;
                val = 0;
            }
        }
        printf("w[0] is 0x%08X.\n",w[0]);
        printf("w[1] is 0x%08X.\n",w[1]);
        printf("w[2] is 0x%08X.\n",w[2]);
        printf("w[3] is 0x%08X.\n",w[3]);
        printf("w[4] is 0x%08X.\n",w[4]);
        printf("w[5] is 0x%08X.\n",w[5]);
        printf("w[6] is 0x%08X.\n",w[6]);
        printf("w[7] is 0x%08X.\n",w[7]);
        printf("w[8] is 0x%08X.\n",w[8]);
        printf("w[9] is 0x%08X.\n",w[9]);
        printf("w[10] is 0x%08X.\n",w[10]);
        printf("w[11] is 0x%08X.\n",w[11]);
        printf("w[12] is 0x%08X.\n",w[12]);
        printf("w[13] is 0x%08X.\n",w[13]);
        printf("w[14] is 0x%08X.\n",w[14]);
        printf("w[15] is 0x%08X.\n",w[15]);
        //write message to hardware
        printf("write_process is here!!!\n");
        write_block();
        
    }
    //wait for generation digest
    wait_ready();
    //read digest from hardware
    read_digest();
}

void check_sha256(int* errors){
    //
    // Make sure no irq pending
    //
    // Disable irq within user plugin peripherals.
    UP_APB_CTRL = 0;
    // Clear pending int
    UP_APB_CMD = UP_CMD_CLR_INT_BIT;
    //
    // Global enable User plugin interrupt
    //
    // Clear all events
    ECP = 0xFFFFFFFF;
    // Clear all interrupts
    ICP = 0xFFFFFFFF;
    int_enable();
    IER = IER | (1 << IRQ_UP_IDX); // Enable User plugin interrupt

    g_up_int_triggers = 0;
    // Enable interrupt within user plugin peripheral
    UP_APB_CTRL = UP_CTRL_INT_EN_BIT;
    printf("User Plugin Interrupt has been enabled\n");
    
    UP_APB_CMD = UP_CMD_SET_INT_BIT;
    //input the information to be encrypted
    //pre_processing
    //entering message to hardware for encrypting    
    //unsigned char msg_in[] = "a";
    //unsigned char msg_in[] = "aaabbbcccdddeeefff";
    const char msg_in[] = "hello world!";
    /*unsigned char msg_in[] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                             bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\
                             ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\
                             ddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";*/
    handle_message(msg_in,strlen(msg_in));
    //do check result of sha256
    do_check_sha256(errors,2);
}

int main(int argc,char*argv[]){
#if 0
    uart_set_cfg(0, 7);
#endif
    int errors = 0;
    //there for check sha256
    check_sha256(&errors); 
    
    return (errors != 0); 
}
