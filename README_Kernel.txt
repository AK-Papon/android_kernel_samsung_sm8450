################################################################################
1. How to Build
        - get Toolchain
                get the proper toolchain packages from AOSP or CodeSourcery or ETC.
                (Download link : https://opensource.samsung.com/uploadSearch?searchValue=toolchain )
                Please decompress in 'kernel_platform' folder
                (toolchain path : kernel_platform\prebuilts, kernel_platform\prebuilts-master)

        - Set and export target config
                1. target config
                        BUILD_TARGET=b0q_gbl_openx
                        export MODEL=$(echo ${BUILD_TARGET} | cut -d'_' -f1)
                        export PROJECT_NAME=${MODEL}
                        export REGION=$(echo ${BUILD_TARGET} | cut -d'_' -f2)
                        export CARRIER=$(echo ${BUILD_TARGET} | cut -d'_' -f3)
                        export TARGET_BUILD_VARIANT= user
                        
                2. Chipset common config
                        CHIPSET_NAME=waipio
                        export ANDROID_BUILD_TOP=$(pwd)
                        export TARGET_PRODUCT=gki
                        export TARGET_BOARD_PLATFORM=gki

                        export ANDROID_PRODUCT_OUT=${ANDROID_BUILD_TOP}/out/target/product/${MODEL}
                        export OUT_DIR=${ANDROID_BUILD_TOP}/out/msm-${CHIPSET_NAME}-${CHIPSET_NAME}-${TARGET_PRODUCT}

                        # for Lcd(techpack) driver build
                        export KBUILD_EXTRA_SYMBOLS=${ANDROID_BUILD_TOP}/out/vendor/qcom/opensource/mmrm-driver/Module.symvers

                        # for Audio(techpack) driver build
                        export MODNAME=audio_dlkm

                        export KBUILD_EXT_MODULES="../vendor/qcom/opensource/datarmnet-ext/wlan                           ../vendor/qcom/opensource/datarmnet/core                           ../vendor/qcom/opensource/mmrm-driver                           ../vendor/qcom/opensource/audio-kernel                           ../vendor/qcom/opensource/camera-kernel                           ../vendor/qcom/opensource/display-drivers/msm                         "

        - Start to trigger build
                3. build kernel
                        RECOMPILE_KERNEL=1 ./kernel_platform/build/android/prepare_vendor.sh sec ${TARGET_PRODUCT}


2. Output files
        - Kernel : arch/${__arch_name}/boot/Image
        - module : drivers/*/*.ko

3. How to Clean
        Change to OUTPUT_DIR folder
        EX) /home/dpi/qb5_8816/workspace/P4_1716/android/out/target/product/b0q/out
        $ make clean
################################################################################
