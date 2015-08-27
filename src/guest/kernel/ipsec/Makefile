MODULE_NAME = virtio_ipsec_module

SRC := virtio_ipsec.c ../../common/ipsec/virtio_ipsec_msg.c
KDIR	:= ~subha/ls2-linux

$(MODULE_NAME)-objs = $(SRC:.c=.o)

obj-m := $(MODULE_NAME).o
PWD	:= $(shell pwd)


G_IPSEC_LA := /home/subha/g_ipsec_la/src/guest/kernel/ipsec/


EXTRA_CFLAGS	:= -I$(PWD) -I$(G_IPSEC_LA)/  -I$(G_IPSEC_LA)../../common/ipsec -v

all:
	make -C $(KDIR) M=$(PWD) modules

clean:
	make -C $(KDIR) M=$(PWD) clean
