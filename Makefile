ifneq ($(TOPDIR),)
include $(CURDIR)/openwrt/Makefile
$(eval $(call BuildPackage,rahawrt))
else
.PHONY: test build check apk
export PYTHONDONTWRITEBYTECODE=1
test:
	python3 -m unittest discover -s tests -v
apk:
	python3 scripts/build-apk.py
check:
	python3 -m compileall -q rahawrt tests scripts
	python3 -c "compile(open('openwrt/files/rahawrt.cgi').read(),'rahawrt.cgi','exec')"
	node --check web/app.js
	node --check scripts/test-browser.cjs
	sh -n scripts/install.sh
	sh -n scripts/router.sh
	sh -n scripts/dev-setup.sh
	sh -n scripts/browser-setup.sh
	sh -n scripts/apk-setup.sh
	sh -n scripts/packaging-setup.sh
	sh -n scripts/test-sdk.sh
	sh -n scripts/sdk-build-inside.sh
	sh -n scripts/uhttpd-setup.sh
	sh -n openwrt/files/rahawrt.guard
	sh -n openwrt/files/rahawrt.init
build:
	python3 scripts/build.py
	python3 scripts/build-ipk.py
endif
