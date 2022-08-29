try:
	from binaryninjaui import (UIAction, UIActionHandler, Menu)

	from . import keypatch

	UIAction.registerAction("Keypatch")
	UIActionHandler.globalActions().bindAction("Keypatch", UIAction(keypatch.launch_keypatch))
	Menu.mainMenu("Tools").addAction("Keypatch", "Keypatch")
except ModuleNotFoundError:
	# probably being loaded by headless BinaryNinja
	pass
