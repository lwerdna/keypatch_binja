try:
	from binaryninjaui import (UIAction, UIActionHandler, Menu)

	from . import keypatch

	UIAction.registerAction("KEYPATCH")
	UIActionHandler.globalActions().bindAction("KEYPATCH", UIAction(keypatch.launch_keypatch))
	Menu.mainMenu("Tools").addAction("KEYPATCH", "KEYPATCH")
except ModuleNotFoundError:
	# probably being loaded by headless BinaryNinja
	pass
