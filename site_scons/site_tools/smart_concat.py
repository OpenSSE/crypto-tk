import SCons

def smart_concat(l1, l2):
    if l1 == None:
        return l2
    elif l2 == None:
        return l1
    else:
        return l1 + l2
