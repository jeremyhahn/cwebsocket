################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../src/cwebsocket/subprotocol/echo/echo_client.c \
../src/cwebsocket/subprotocol/echo/echo_server.c 

OBJS += \
./src/cwebsocket/subprotocol/echo/echo_client.o \
./src/cwebsocket/subprotocol/echo/echo_server.o 

C_DEPS += \
./src/cwebsocket/subprotocol/echo/echo_client.d \
./src/cwebsocket/subprotocol/echo/echo_server.d 


# Each subdirectory must supply rules for building sources it contributes
src/cwebsocket/subprotocol/echo/%.o: ../src/cwebsocket/subprotocol/echo/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: Cross GCC Compiler'
	arm-linux-gnueabihf-gcc -I/storage/sources/rpi/usr/include -I/storage/sources/rpi/usr/lib -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


