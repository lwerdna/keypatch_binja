try:
	from binaryninjaui import (UIAction, UIActionHandler, Menu)

	from . import keypatch

	UIAction.registerAction("KEYPATCH\\Patcher")
	UIAction.registerAction("KEYPATCH\\Fill Range")
	UIActionHandler.globalActions().bindAction("KEYPATCH\\Patcher", UIAction(keypatch.launch_patcher))
	UIActionHandler.globalActions().bindAction("KEYPATCH\\Fill Range", UIAction(keypatch.launch_fill_range))
	Menu.mainMenu("Tools").addAction("KEYPATCH\\Patcher", "Patcher")
	Menu.mainMenu("Tools").addAction("KEYPATCH\\Fill Range", "Fill Range")
except ModuleNotFoundError:
	# probably being loaded by headless BinaryNinja
	pass
