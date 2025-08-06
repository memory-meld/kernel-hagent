ccflags-y += -DDEFAULT_SYMBOL_NAMESPACE=DEMETER

obj-$(CONFIG_DEMETER) += demeter_placement.o

demeter_placement-objs += module.o sysfs.o core.o vector.o sds.o mt19937.o

obj-$(CONFIG_DEMETER_TEST) += demeter_test.o

demeter_test-objs += test_wait_event.o

obj-$(CONFIG_DEMETER) += demeter_balloon.o

demeter_balloon-objs += balloon.o

