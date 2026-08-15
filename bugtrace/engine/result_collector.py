class ResultCollector:

    def __init__(self):
        self.results = []

    def add(self, findings):
        if findings:
            self.results.extend(findings)

    def get_all(self):
        return self.results

    def total(self):
        return len(self.results)
