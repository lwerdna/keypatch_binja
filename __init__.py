import sys
import binaryninja

version_problem = False
if (sys.version_info.major, sys.version_info.minor) == (3, 10):
    import platform
    if (platform.system(), platform.machine()) == ('Darwin', 'arm64'):
        binaryninja.log_error('I rely on keystone-engine which has install issues on Python 3.10 arm64 macs.', 'Keypatch plugin')
        binaryninja.log_error('Please upgrade your python version to >= 3.11.', 'Keypatch plugin')
        version_problem = True

if not version_problem:
    if binaryninja.core_ui_enabled():
        from binaryninjaui import (UIAction, UIActionHandler, Menu)

        from . import keypatch

        UIAction.registerAction("Keypatch")
        UIActionHandler.globalActions().bindAction("Keypatch", UIAction(keypatch.launch_keypatch))
        Menu.mainMenu("Plugins").addAction("Keypatch", "Keypatch")
    else:
        # probably being loaded by headless BinaryNinja
        pass
