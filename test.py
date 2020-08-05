from colorama import init
from colorama import Fore, Back, Style

init()

print(Fore.RED + 'some red text')
print(Fore.GREEN + 'and with a green background')
print(Fore.BLUE + 'and with a green background')
print(Fore.MAGENTA+Style.BRIGHT+ 'and with a green background')
print(Fore.YELLOW+Style.DIM+ 'and with a green background')
#print(Style.RESET_ALL)
print('back to normal now')


#Fore.WHITE+Style.BRIGHT+
#Fore.RED+Style.BRIGHT+
