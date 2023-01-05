# install/uninstall via link

.PHONY: install uninstall

install:
	@if [ -L "$(BN_PLUGINS)/keypatch" ]; then \
		echo "already installed"; \
	else \
		echo "installing"; \
		ln -s "$(PWD)" "$(BN_PLUGINS)/keypatch"; \
	fi

uninstall:
	@if [ -L "$(BN_PLUGINS)/keypatch" ]; then \
		echo "uninstalling"; \
		rm "$(BN_PLUGINS)/keypatch"; \
	else \
		echo "not installed"; \
	fi

