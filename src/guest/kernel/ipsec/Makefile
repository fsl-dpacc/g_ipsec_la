SRC	:= virtio_ipsec.c ../common/virtio_ipsec_msg.c

KDIR=

#(MODULE_NAME)-objs = $(SRC:.c=.o)

obj-m +=virtio_ipsec.o

PWD:$(shell pwd)

EXTRA_CFLAGS	:= -I$(PWD)/ -I../common/

all:
	make -C $(KDIR) M=$(PWD) modules

clean:
	make -C $(KDIR) M=$(PWD) clean
