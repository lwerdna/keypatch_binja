try:
	from binaryninjaui import (UIAction, UIActionHandler, Menu)

	from . import keypatch

	UIAction.registerAction("KEYPATCH\\Patcher")
	UIAction.registerAction("KEYPATCH\\Fill Range")
	UIAction.registerAction("KEYPATCH\\Search")
	UIActionHandler.globalActions().bindAction("KEYPATCH\\Patcher", UIAction(keypatch.launch_patcher))
	UIActionHandler.globalActions().bindAction("KEYPATCH\\Fill Range", UIAction(keypatch.launch_fill_range))
	UIActionHandler.globalActions().bindAction("KEYPATCH\\Search", UIAction(keypatch.launch_search))
	Menu.mainMenu("Tools").addAction("KEYPATCH\\Patcher", "Patcher")
	Menu.mainMenu("Tools").addAction("KEYPATCH\\Fill Range", "Fill Range")
	Menu.mainMenu("Tools").addAction("KEYPATCH\\Search", "Search")
except ModuleNotFoundError:
	# probably being loaded by headless BinaryNinja
	pass
