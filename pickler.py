import pickle
import os
import idc
import sys

class Pickler:
    def __init__(self):
        self.pickle_fn = self.get_pickle_fn()

    def get_pickle_fn(self):
        exe_fn = idc.GetInputFile()
        md5 = idc.GetInputMD5()
        fn = "%s.%s.pickle"%(exe_fn, md5)
        return fn

    def can_load_state(self):
        return os.path.exists(self.pickle_fn)

    def save_state(self, state):
        f = open(self.pickle_fn, "w")
        try:
            pickle.dump(state, f)
        except:
            f.close()
            os.remove(self.pickle_fn)
            raise

        f.close()

    def load_state(self):
        f = open(self.pickle_fn, "r")
        state = pickle.load(f)
        f.close()
        return state
