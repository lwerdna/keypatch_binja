try:
	from binaryninjaui import (UIAction, UIActionHandler, Menu)

	from . import keypatch

	UIAction.registerAction("KEYPATCH\\Patcher")
	UIActionHandler.globalActions().bindAction("KEYPATCH\\Patcher", UIAction(keypatch.launch_patcher))
	Menu.mainMenu("Tools").addAction("KEYPATCH\\Patcher", "Patcher")
except ModuleNotFoundError:
	# probably being loaded by headless BinaryNinja
	pass
