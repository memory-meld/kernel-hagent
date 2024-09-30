ccflags-y += -DDEFAULT_SYMBOL_NAMESPACE=HAGENT

obj-$(CONFIG_HAGENT) += hagent_placement.o

hagent_placement-objs += module.o sysfs.o core-new.o vector.o sds.o mt19937.o

obj-$(CONFIG_HAGENT_TEST) += hagent_test.o

hagent_test-objs += test_wait_event.o

obj-$(CONFIG_HAGENT) += hagent_balloon.o

hagent_balloon-objs += balloon.o

