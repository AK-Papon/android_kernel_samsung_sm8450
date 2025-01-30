LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE:= libexifa
LOCAL_MODULE_TAGS := optional
LOCAL_REQUIRED_MODULES := libexifa.camera.samsung

$(call reg_lib_to_system_public, libexifa.camera.samsung.so, $(SYS_PUBLIC_LIB_CAMERA_TXT))

include $(BUILD_PHONY_PACKAGE)