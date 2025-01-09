from tkinter import *
from tkinter import ttk
import string
import random


def add_tab(notebook, tab_name):
    new_tab = Frame(notebook)
    notebook.add(new_tab, text=f"{tab_name}")
    return new_tab


def add_salt():
    salt = "".join(random.SystemRandom().choice(
        string.ascii_letters + string.digits) for i in range(16))
    return salt
