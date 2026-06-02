from pathlib import Path
from setuptools import setup
from setuptools.command.install import install
from setuptools.command.develop import develop


class PostInstall(install):
    def run(self) -> None:
        super().run()

        if self.install_lib:
            install_dir = Path(self.install_lib)
            marker_file = install_dir / "aiolrucache" / ".post_install_ran"
            marker_file.parent.mkdir(parents=True, exist_ok=True)
            marker_file.write_text("PostInstall hook executed successfully")


class PostDevelop(develop):
    def run(self) -> None:
        super().run()
        print("post-develop hook ran successfully")


setup(cmdclass={"install": PostInstall, "develop": PostDevelop})
