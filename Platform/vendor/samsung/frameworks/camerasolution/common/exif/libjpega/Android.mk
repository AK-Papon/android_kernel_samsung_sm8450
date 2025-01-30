LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)

LOCAL_MODULE:= libjpega
LOCAL_MODULE_TAGS := optional
LOCAL_REQUIRED_MODULES := libjpega.camera.samsung

$(call reg_lib_to_system_public, libjpega.camera.samsung.so, $(SYS_PUBLIC_LIB_CAMERA_TXT))

include $(BUILD_PHONY_PACKAGE)