################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../src/cwebsocket/client.c \
../src/cwebsocket/common.c \
../src/cwebsocket/server.c \
../src/cwebsocket/utf8.c 

OBJS += \
./src/cwebsocket/client.o \
./src/cwebsocket/common.o \
./src/cwebsocket/server.o \
./src/cwebsocket/utf8.o 

C_DEPS += \
./src/cwebsocket/client.d \
./src/cwebsocket/common.d \
./src/cwebsocket/server.d \
./src/cwebsocket/utf8.d 


# Each subdirectory must supply rules for building sources it contributes
src/cwebsocket/%.o: ../src/cwebsocket/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: Cross GCC Compiler'
	arm-linux-gnueabihf-gcc -I/storage/sources/rpi/usr/include -I/storage/sources/rpi/usr/lib -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


