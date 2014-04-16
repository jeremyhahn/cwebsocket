################################################################################
# Automatically-generated file. Do not edit!
################################################################################

-include ../makefile.init

RM := rm -rf

# All of the sources participating in the build are defined here
-include sources.mk
-include src/cwebsocket/subprotocol/echo/subdir.mk
-include src/cwebsocket/subdir.mk
-include src/subdir.mk
-include subdir.mk
-include objects.mk

ifneq ($(MAKECMDGOALS),clean)
ifneq ($(strip $(C_DEPS)),)
-include $(C_DEPS)
endif
endif

-include ../makefile.defs

# Add inputs and outputs from these tool invocations to the build variables 

# All Target
all: cwebsocket

# Tool invocations
cwebsocket: $(OBJS) $(USER_OBJS)
	@echo 'Building target: $@'
	@echo 'Invoking: Cross GCC Linker'
	arm-linux-gnueabihf-gcc -L/storage/sources/rpi/usr/include -L/storage/sources/rpi/usr/lib/arm-linux-gnueabihf -L/storage/sources/rpi/usr/lib -o "cwebsocket" $(OBJS) $(USER_OBJS) $(LIBS)
	@echo 'Finished building target: $@'
	@echo ' '

# Other Targets
clean:
	-$(RM) $(OBJS)$(C_DEPS)$(EXECUTABLES) cwebsocket
	-@echo ' '

.PHONY: all clean dependents
.SECONDARY:

-include ../makefile.targets
