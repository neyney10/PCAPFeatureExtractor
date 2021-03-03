import numpy as np

class Stats: # INTERFACE
    def average(self):
        pass

    def median(self):
        pass

    def mode(self):
        pass 

    def variance(self):
        pass
    
    def std_deviation(self):
        pass

    def coeff_of_variation(self):
        pass

    def skew_from_median(self):
        pass

    def skew_from_mode(self):
        pass 
    
    def min(self):
        pass
    
    def max(self):
        pass


class StatsCollection(Stats): 
    def __init__(self, stats) -> None:
        self.inner_collection = stats

    def average(self):
        avgs = np.empty(len(self.inner_collection))
        for i, stats in enumerate(self.inner_collection):
            avgs[i] = stats.average()

        return avgs

    def median(self):
        pass

    def mode(self):
        pass 

    def variance(self):
        pass
    
    def std_deviation(self):
        pass

    def coeff_of_variation(self):
        pass

    def skew_from_median(self):
        pass

    def skew_from_mode(self):
        pass 
    
    def min(self) -> float:
        return np.min(self.values)
    
    def max(self) -> float:
        return np.max(self.values)

class IterableStats(Stats):
    '''
        Works only on iterables such as lists.
                                                '''
    def __init__(self, values) -> None:
        self.values = values

    def average(self) -> float:
        return np.average(self.values)
    
    def median(self) -> float:
        return np.median(self.values)

    def mode(self) -> float:
        raise Exception('Not implemented') 

    def variance(self) -> float:
        return np.var(self.values)
    
    def std_deviation(self) -> float:
        return np.std(self.values)

    def coeff_of_variation(self) -> float:
        if self.average() != 0:
            return self.std_deviation() / self.average()
        else:
            return None

    def skew_from_median(self) -> float:
        #  Skew = 3 * (Mean – Median) / Standard Deviation
        if self.std_deviation() != 0:
            return 3 * (self.average() - self.median()) / self.std_deviation()
        else:
            return None

    def skew_from_mode(self) -> float:
        #  Skew =  (Mean – Mode) / Standard Deviation
        if self.std_deviation() != 0:
            return (self.average() - self.mode()) / self.std_deviation()
        else:
            return None
    
    def min(self):
        if len(self.values) > 0:
            return np.min(self.values)
        else:
            return None
    
    def max(self):
        if len(self.values) > 0:
            return np.max(self.values)
        else:
            return None

       