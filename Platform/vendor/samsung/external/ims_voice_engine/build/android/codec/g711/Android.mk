
LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)

LOCAL_MODULE := libpcmnb

LOCAL_C_INCLUDES := \
	$(LOCAL_PATH)/../../../../codec/g711/float_c/inc

LOCAL_SRC_FILES := \
	../../../../codec/g711/float_c/src/g711.c
	
LOCAL_CFLAGS := $(PV_CFLAGS) -fPIC

LOCAL_ARM_MODE := arm

LOCAL_MULTILIB := 64

include $(BUILD_SHARED_LIBRARY)