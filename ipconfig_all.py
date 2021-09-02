from tkinter import *
from tkinter import ttk
import subprocess

def ipconfig_dump():
    ipconfig = subprocess.check_output('ipconfig /all')
    ipconfig = ipconfig.decode()

    parse = ipconfig.split('\r\n\r\n')

    parse_len = len(parse)

    interfaces = []
    for i in range(0, parse_len, 2):
        line1 = parse[i]
        line2 = parse[i+1]
        interface = line1 + '\n' + line2
        interfaces.append(interface.strip())

    list = []
    for interface in interfaces:
        i_list = []

        tmp = interface.split('\n')
        i_list.append(tmp[0])
        for i in range(1, len(tmp)):
            line = tmp[i]
            record_list = []
            record_list.append(line[:38].strip())
            record_list.append(line[39:].strip())
            i_list.append(record_list)
        list.append(i_list)
    return list

class App(Frame):
    def __init__(self, master):
        Frame.__init__(self, master)
        self.master = master

        self.initUI()

    def initUI(self):
        self.app_config()

        # =============================
        tree = ttk.Treeview(self)
        tree.pack(fill=BOTH, expand=TRUE)

        tree["columns"] = ('one')
        tree.column("#0", width=270, minwidth=350, stretch=YES)
        tree.column("one", width=150, minwidth=200, stretch=YES)

        tree.heading("#0", text="Name", anchor=W)
        tree.heading("one", text="Values", anchor=W)

        dumps = ipconfig_dump()
        for i in dumps:
            interface = tree.insert('', END, text=i[0])
            for j in range(1, len(i)):
                line = i[j]
                tree.insert(interface, END, text=line[0], values=(line[1],))

    def app_config(self):
        self.master.title('ipconfig /all')
        self.configure(background='blue')
        self.pack(fill=BOTH, expand=True)



root = Tk()
app = App(root)
root.mainloop()
