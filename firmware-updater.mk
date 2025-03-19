################################################################################
#
# firmware-updater
#
################################################################################

FIRMWARE_UPDATER_VERSION = 1.0
FIRMWARE_UPDATER_LICENSE = GPL-2.0
FIRMWARE_UPDATER_SITE_METHOD = local
FIRMWARE_UPDATER_SITE = $(FIRMWARE_UPDATER_PKGDIR)
FIRMWARE_UPDATER_SOURCE = firmware-updater.c

define FIRMWARE_UPDATER_BUILD_CMDS
	$(TARGET_CC) $(TARGET_CFLAGS) $(TARGET_LDFLAGS) \
		$(FIRMWARE_UPDATER_PKGDIR)/firmware-updater.c -o $(@D)/firmware-updater
endef

define FIRMWARE_UPDATER_INSTALL_TARGET_CMDS
	$(INSTALL) -D -m 0755 $(@D)/firmware-updater $(TARGET_DIR)/usr/bin/firmware-updater
endef

$(eval $(generic-package))