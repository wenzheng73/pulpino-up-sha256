#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>
#include "int.h"
#include "event.h"
#include "cpu_hal.h"
#include "uart.h"
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
    //printf("address is 0x%x.\n",address);
    //printf("message is 0x%08X.\n",word);
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
    printf("Hash is calculated completely!!!<_>\n");
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

    unsigned int expect_out [32] = {
                  //message0 ""(empty)expected output
                  0xE3B0C442, 0x98FC1C14, 0x9AFBF4C8, 0x996FB924,
                  0x27AE41E4, 0x649B934C, 0xA495991B, 0x7852B855,     

                  //message1 "hello world!"'s expected output
                  0x7509E5BD, 0xA0C762D2, 0xBAC7F90D, 0x758B5B22, 
                  0x63FA01CC, 0xBC542AB5, 0xE3DF163B, 0xE08E6CA9,
      
                  //message2 "abcdbcdecdefdefg...efghfghigmnopnopq"'s(56byte) expected output
                  0x248D6A61, 0xD20638B8, 0xE5C02693, 0x0C3E6039,
                  0xA33CE459, 0x64FF2167, 0xF6ECEDD4, 0x19DB06C1,
                  
                                          
                  //message3 "aaa...bbb...ccc...ddd"(0x61..62..63..64)'s(90byte) expected output
                  0x6B2EC791, 0x70F50EA5, 0x7B886DC8, 0x1A2CF787, 
                  0x21C651A0, 0x02C8365A, 0x524019A7, 0xED5A8A40

                  }; 
 
    for(int i = 0; i < 8; i++ ){
        if( digest_data[i] != expect_out[i + msg_num * 8] ){
            ++(*errors);
            printf("EXPECTED OUTPUT IS 0x%08X, WRONG OUTPUT IS 0x%08X \n", expect_out[i + msg_num * 8], digest_data[i]);
        }

        else{
            printf("OUT RIGHT! OUT IS 0x%08X \n", digest_data[i] );  
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
        for (size_t i = 0; i < 16; i++){
            printf("w[%d] is 0x%08X.\n",i,w[i]);
        }
        //write message to hardware
        printf("write_process is here!!!\n");
        write_block();
        //
        if (idx == 0){
            write_word(ADDR_CTRL, (CTRL_MODE_VALUE + CTRL_INIT_VALUE));
        }
        else{ 
            write_word(ADDR_CTRL, (CTRL_MODE_VALUE + CTRL_NEXT_VALUE)); 
        }
        //wait for generation digest
        wait_ready();
    }
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
    
    //input the information to be encrypted
    //pre_processing
    //entering message to hardware for encrypting 
    //The information msg_in0 to be encrypted is empty(no information, size: 0byte)  
    //The information msg_in1 to be encrypted is "hello world!"(size: 11byte)  
    //The information msg_in2 to be encrypted is "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" (size: 56byte) 
    //The information msg_in3 to be encrypted is "aaaaaaaaaaaaaaaa......aaaaaaaaaaa" (size: 90byte > 56byte) 
    const char msg_in0[] = ""; 
    const char msg_in1[] = "hello world!";
    const char msg_in2[] = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    const char msg_in3[] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    //Set interrupt pending
    UP_APB_CMD = UP_CMD_SET_INT_BIT;
    handle_message(msg_in0,strlen(msg_in0));
    //do check result of sha256
    do_check_sha256(errors,0);
    
    //Set interrupt pending
    UP_APB_CMD = UP_CMD_SET_INT_BIT;
    handle_message(msg_in1,strlen(msg_in1));
    //do check result of sha256
    do_check_sha256(errors,1);
    
    //Set interrupt pending
    UP_APB_CMD = UP_CMD_SET_INT_BIT;
    handle_message(msg_in2,strlen(msg_in2));
    //do check result of sha256
    do_check_sha256(errors,2);
    
    //Set interrupt pending
    UP_APB_CMD = UP_CMD_SET_INT_BIT;
    handle_message(msg_in3,strlen(msg_in3));
    //do check result of sha256
    do_check_sha256(errors,3);

}

int main(int argc,char*argv[]){
#if 0
    uart_set_cfg(0, 7);
#endif
    int errors = 0;
    //there for check sha256
    check_sha256(&errors); 
    printf("ERRORS: %d\n", errors);
    return (errors != 0); 
}
