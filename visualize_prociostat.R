#
# visualize_prociostat.R
# $Id$
#
# Usage
#  R -f visualize_prociostat.R --args process.1.txt

src_csv <- commandArgs(trailingOnly=TRUE)[1]
csv <- read.csv(src_csv)

output_filename = gsub("/*$", ".png", src_csv) ## manipulate .png filename
png(output_filename, width=800, height=600)

# scale
iorate_lim = c(0, max(csv$delta_read_bytes, csv$delta_write_bytes) * 1.1);
cpurate_lim = c(0, max(csv$delta_utime, csv$delta_stime) * 1.1);

par(oma = c(0, 0, 0, 2))
par(pch=20)
plot(x=csv$time, y=csv$delta_write_bytes, xlab="", ylab="KB/s", ylim=iorate_lim, col='pink', axes = FALSE);
par(new = TRUE)
plot(x=csv$time, y=csv$delta_read_bytes, xlab="", ylab="", ylim=iorate_lim, col='lightgreen', axes = FALSE);
mtext('cpu%', side=4, line=3)

axis(1) # draw X axis
axis(2) # draw Y axis

# CPU time
par(new = TRUE)
plot(x=csv$time, y=csv$delta_utime, type="l", xlab='time[epoch]', ylab='', ylim=cpurate_lim, col='orange', axes = FALSE)
par(new = TRUE)
plot(x=csv$time, y=csv$delta_stime, type="l", xlab='', ylab='', ylim=cpurate_lim, col='red', axes = FALSE)

# blocked ticks
par(new = TRUE)
plot(x=csv$time, y=csv$delta_delayacct_blkio_ticks, type="l", xlab='', ylab='', ylim=c(0,200), col='purple', axes = FALSE)
axis(4)
box()
legend("topleft", legend=c("read", "write", "cpu%", "sys%", "blocked ticks"), col = c("lightgreen", "pink", "orange","red", "purple"), lty=c(1,1,1,1))
dev.off()
