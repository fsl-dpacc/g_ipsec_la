SRC	:= virtio_ipsec.c ../../common/ipsec/virtio_ipsec_msg.c
PWD	:= $(shell pwd)

KDIR	:= ~subha/ls2-linux
G_IPSEC_LA := /home/subha/g_ipsec_la/src/guest/kernel/ipsec/


#(MODULE_NAME)-objs = $(SRC:.c=.o)

obj-m +=virtio_ipsec.o


EXTRA_CFLAGS	:= -I$(PWD) -I$(G_IPSEC_LA)/  -I$(G_IPSEC_LA)../../common/ipsec -v

all:
	make -C $(KDIR) M=$(PWD) modules

clean:
	make -C $(KDIR) M=$(PWD) clean
