import fire, subprocess, yaml

class ScanDocker():
    #Функция чтения политики из файла
    def ReadPolicyFile(PolicyFileName="policy.yml"):
        with open(PolicyFileName, 'r') as PFile:
            policy = yaml.safe_load(PFile) or {}
        policy_dict = policy.get("Policy")
        if isinstance(policy_dict, dict) and "LevelUp" in policy_dict:
            return policy_dict["LevelUp"]
        else:
            return ['HIGH', 'CRITICAL']
        
    # Функция для анализа вывода
    def AnalysisOut(result):
        levels = ScanDocker.ReadPolicyFile()
        found_lines = [
            line for line in result.splitlines()
            if any(level in line for level in levels)
        ]
        if found_lines:
            return "\n".join(found_lines)
        else:
            return "Уязвимостей нет"
        
    # Функция для сканирования образов Docker
    def scan(self, ImageID):
        Args = []
        Args = ["trivy", "image", ImageID]
        result = subprocess.run(
            Args,
            stdout = subprocess.PIPE,
            stderr = subprocess.STDOUT,
            universal_newlines = True)
        filtered_output = ScanDocker.AnalysisOut(result.stdout)
        return filtered_output

if __name__ == "__main__":
    obj = ScanDocker()
    fire.Fire(obj)
