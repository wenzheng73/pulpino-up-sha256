#ifndef _USER_PLUGIN_APB_H_
#define _USER_PLUGIN_APB_H_

#include <pulpino.h>

#define UP_APB_REG_CTRL    ( USER_PLUGIN_APB_BASE_ADDR + 0x04 )
#define UP_APB_REG_CMD     ( USER_PLUGIN_APB_BASE_ADDR + 0x08 )
#define UP_APB_REG_STATUS  ( USER_PLUGIN_APB_BASE_ADDR + 0x0C )

#define SHA256_REG_ADDRESS ( USER_PLUGIN_APB_BASE_ADDR + 0x10 )
#define SHA256_REG_MESSAGE ( USER_PLUGIN_APB_BASE_ADDR + 0x14 )
#define SHA256_REG_RW      ( USER_PLUGIN_APB_BASE_ADDR + 0x18 )
#define SHA256_REG_DIGEST  ( USER_PLUGIN_APB_BASE_ADDR + 0x1C )


#define UP_APB_CTRL       REG(UP_APB_REG_CTRL)
#define UP_APB_CMD        REG(UP_APB_REG_CMD)
#define UP_APB_STATUS     REG(UP_APB_REG_STATUS)

#define SHA256_ADDRESS	  REG(SHA256_REG_ADDRESS)
#define SHA256_MESSAGE	  REG(SHA256_REG_MESSAGE)
#define SHA256_RW	      REG(SHA256_REG_RW)
#define SHA256_DIGEST	  REG(SHA256_REG_DIGEST)



#define UP_CTRL_INT_EN_BIT (1 << 0)

#define UP_CMD_CLR_INT_BIT (1 << 0)
#define UP_CMD_SET_INT_BIT (1 << 1)

#define UP_STATUS_INT_BIT  (1 << 0)

#define CTRL_HASH_RW_CLR   (1 << 0)
#define CTRL_HASH_RW_EN    (1 << 1)

#define CTRL_HASH_EN_INT_EN 0x03
#define CTRL_HASH_CLR_INT_CLR 0x00

//----------------------------------------------------------------
// Internal constant and parameter definitions.
//----------------------------------------------------------------
// The address map.
#define ADDR_NAME0        0x00
#define ADDR_NAME1        0x01
#define ADDR_VERSION      0x02

#define ADDR_CTRL         0x08
#define CTRL_INIT_VALUE   0x01
#define CTRL_NEXT_VALUE   0x02
#define CTRL_MODE_VALUE   0x04

#define ADDR_STATUS       0x09
#define STATUS_READY_BIT  0x00
#define STATUS_VALID_BIT  0x01

#define ADDR_BLOCK0     0x10
#define ADDR_BLOCK1     0x11
#define ADDR_BLOCK2     0x12
#define ADDR_BLOCK3     0x13
#define ADDR_BLOCK4     0x14
#define ADDR_BLOCK5     0x15
#define ADDR_BLOCK6     0x16
#define ADDR_BLOCK7     0x17
#define ADDR_BLOCK8     0x18
#define ADDR_BLOCK9     0x19
#define ADDR_BLOCK10    0x1a
#define ADDR_BLOCK11    0x1b
#define ADDR_BLOCK12    0x1c
#define ADDR_BLOCK13    0x1d
#define ADDR_BLOCK14    0x1e
#define ADDR_BLOCK15    0x1f

#define ADDR_DIGEST0    0x20
#define ADDR_DIGEST1    0x21
#define ADDR_DIGEST2    0x22
#define ADDR_DIGEST3    0x23
#define ADDR_DIGEST4    0x24
#define ADDR_DIGEST5    0x25
#define ADDR_DIGEST6    0x26
#define ADDR_DIGEST7    0x27

#define SHA224_MODE     0x00
#define SHA256_MODE     0x01

#endif
