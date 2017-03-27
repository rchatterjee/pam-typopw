all: typtops

typtops:
	export PYTHONHASHSEED=2354
	pyinstaller -y --nowindow --onedir -d typtops.spec
	cp dist/typtops/typtop dist/typtops/typtop.root
	sudo chown root:shadow dist/typtops/typtop.root
	sudo chmod g+s dist/typtops/typtop.root

clean:
	rm -rf build/typtops dist/typtops
