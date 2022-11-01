FROM dhub.ncats.dhs.gov:5001/cyhy-core
ENV CYHY_COMMANDER_SRC="/usr/src/cyhy-commander"

LABEL org.opencontainers.image.authors="mark.feldhousen@cisa.dhs.gov"
LABEL org.opencontainers.image.vendor="Cybersecurity and Infrastructure Security Agency"

USER root
WORKDIR ${CYHY_COMMANDER_SRC}

COPY . ${CYHY_COMMANDER_SRC}
RUN pip install --no-cache-dir -r requirements.txt

USER cyhy
WORKDIR ${CYHY_HOME}
CMD ["cyhy-commander", "--debug", "--stdout-log", "commander"]
