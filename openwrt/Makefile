include $(TOPDIR)/rules.mk
PKG_NAME:=rahawrt
PKG_VERSION:=0.1.0
PKG_RELEASE:=1
PKG_LICENSE:=MIT
include $(INCLUDE_DIR)/package.mk

define Package/rahawrt
  PKGARCH:=all
  SECTION:=net
  CATEGORY:=Network
  TITLE:=Persian/English OpenWrt management with PassWall2
  DEPENDS:=+python3 +python3-sqlite3 +ca-bundle +ip-full +uhttpd +nftables-json +luci-app-passwall2
endef

define Package/rahawrt/conffiles
/etc/config/rahawrt
/etc/rahawrt/
endef

define Build/Compile
endef

# Copy the repository as package/rahawrt; this Makefile is included by its root Makefile.
define Package/rahawrt/install
	$(INSTALL_DIR) $(1)/usr/lib/rahawrt/rahawrt $(1)/usr/share/rahawrt/web $(1)/www/wrt $(1)/www/cgi-bin $(1)/etc/init.d $(1)/etc/config $(1)/etc/rahawrt $(1)/usr/share/rahawrt/scripts $(1)/usr/share/doc/rahawrt $(1)/usr/share/rahawrt/public/wrt $(1)/usr/share/rahawrt/public/cgi-bin $(1)/usr/libexec
	$(INSTALL_DATA) $(CURDIR)/openwrt/files/guest.httpd.conf $(1)/usr/share/rahawrt/guest.httpd.conf
	$(INSTALL_DATA) $(CURDIR)/rahawrt/*.py $(1)/usr/lib/rahawrt/rahawrt/
	$(INSTALL_DATA) $(CURDIR)/web/* $(1)/usr/share/rahawrt/web/
	$(INSTALL_DATA) $(CURDIR)/web/* $(1)/usr/share/rahawrt/public/wrt/
	$(INSTALL_DATA) $(CURDIR)/web/* $(1)/www/wrt/
	$(INSTALL_BIN) $(CURDIR)/openwrt/files/rahawrt.cgi $(1)/usr/share/rahawrt/public/cgi-bin/rahawrt
	$(INSTALL_BIN) $(CURDIR)/openwrt/files/rahawrt.cgi $(1)/www/cgi-bin/rahawrt
	$(INSTALL_BIN) $(CURDIR)/openwrt/files/rahawrt.guard $(1)/usr/libexec/rahawrt-guard
	$(INSTALL_BIN) $(CURDIR)/openwrt/files/rahawrt.init $(1)/etc/init.d/rahawrt
	$(INSTALL_BIN) $(CURDIR)/scripts/router.sh $(1)/usr/share/rahawrt/scripts/router.sh
	$(INSTALL_DATA) $(CURDIR)/LICENSE $(CURDIR)/THIRD_PARTY.md $(1)/usr/share/doc/rahawrt/
	chmod 0700 $(1)/etc/rahawrt
	$(INSTALL_CONF) $(CURDIR)/openwrt/files/rahawrt.config $(1)/etc/config/rahawrt
endef
