# Simple wrapper for scripts with printed status messages.
# 
# Running `make` or `make stagex` will leverage the steps below
# to check compatibility and build the binaries via StageX.

.PHONY: stagex compat build load frostd frost-client coordinator participant trusted-dealer zcash-sign dkg

stagex:	compat build
	@echo "stagex build completed via make."

compat:
	@echo "Beginning Compatibility Check step."
	@./docker/compat.sh
	@echo "  [PASS]  Compatibility Check passed."

build:
	@echo "Entering Build step."
	@./docker/build.sh
	@echo "Build step complete."

load:
	@echo "Attempting to load OCI image into local docker image store."
	@./docker/load_image.sh
	@echo "make load step complete."

frostd:
	@echo "Running frostd from image."
	@./docker/run_frostd.sh
	@echo "make frostd step complete."
	
frost-client:
	@echo "Running frost-client from image."
	@./docker/run_frost-client.sh
	@echo "make frost-client step complete."

coordinator:
	@echo "Running coodinator from image."
	@./docker/run_coodinator.sh
	@echo "make coordinator step complete."

participant:
	@echo "Running paticipant from image."
	@./docker/run_participant.sh
	@echo "make participant step complete."
	
trusted-dealer:
	@echo "Running trusted-dealer from image."
	@./docker/run_trusted-dealer.sh
	@echo "make trusted-dealer step complete."

zcash-sign:
	@echo "Running zcash-sign from image."
	@./docker/run_zcash-sign.sh
	@echo "make zcash-sign step complete."

dkg:
	@echo "Running dkg from image."
	@./docker/run_dkg.sh
	@echo "make dkg step complete."
