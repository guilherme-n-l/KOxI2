#!/usr/bin/env Rscript
# Golden fixtures for koxi's Hodges-Lehmann CI and DeLong A12 CI,
# generated with R wilcox.test (exact branch) and pROC ci.auc.
# Regenerate (and lint) under the flake-locked R:
#
#   nix run .#gen-stats-fixtures

suppressMessages({
  library(pROC)
  library(jsonlite)
})

# Untied float samples (wilcox.test falls off the exact CI branch on
# ties); fio-like magnitudes plus their logs, small and asymmetric n.
fio_c <- c(30236.4, 29873.1, 30412.9, 29954.2, 30102.7, 29788.5,
           30051.3, 29912.8, 30187.6, 30298.4)
fio_rs <- c(25911.2, 25640.8, 26023.5, 25733.1, 25989.0, 25580.4,
            25866.7, 25802.6, 26051.9, 25698.3)

hl_cases <- list(
  list(name = "small 4v5", x = c(1.1, 4.2, 6.3, 9.4),
       y = c(2.5, 3.1, 5.7, 7.2, 8.9)),
  list(name = "eight vs eight",
       x = c(12.1, 5.3, 9.2, 1.4, 14.5, 3.6, 8.7, 11.8),
       y = c(2.2, 6.4, 4.1, 13.3, 7.5, 10.6, 15.7, 16.8)),
  list(name = "fio like 10v10", x = fio_rs, y = fio_c),
  list(name = "log fio 10v10", x = log(fio_rs), y = log(fio_c)),
  list(name = "three vs three", x = c(30236.4, 29873.1, 30412.9),
       y = c(25911.2, 25640.8, 26023.5)),
  list(name = "overlapping 6v6", x = c(1.05, 2.15, 3.25, 4.35, 5.45, 6.55),
       y = c(1.5, 2.6, 3.7, 4.8, 5.9, 7.0))
)

hl_entry <- function(case) {
  out <- list(name = case$name, x = case$x, y = case$y, levels = list())
  for (cl in c(0.90, 0.95)) {
    w <- wilcox.test(case$x, case$y, conf.int = TRUE, conf.level = cl,
                     exact = TRUE, alternative = "two.sided")
    out$levels[[sprintf("%.2f", cl)]] <- list(
      estimate = unname(w$estimate),
      lo = w$conf.int[1],
      hi = w$conf.int[2]
    )
  }
  out
}

auc_cases <- list(
  list(name = "clear separation", x = c(5.1, 6.2, 7.3), y = c(1.4, 2.5, 3.6)),
  list(name = "fio like", x = fio_rs, y = fio_c),
  list(name = "overlap", x = c(1.05, 2.15, 3.25, 4.35, 5.45, 6.55),
       y = c(1.5, 2.6, 3.7, 4.8, 5.9, 7.0)),
  list(name = "overlap with ties", x = c(1, 2, 2, 3, 4, 5),
       y = c(2, 3, 3, 4, 4, 6)),
  list(name = "ten vs ten mixed",
       x = c(3.1, 7.2, 1.3, 9.4, 5.5, 2.6, 8.7, 4.8, 6.9, 10.0),
       y = c(2.05, 6.15, 4.25, 8.35, 1.45, 9.55, 3.65, 5.75, 7.85, 0.95))
)

auc_entry <- function(case) {
  # AUC = P(x > y) + 0.5 P(x = y): x are "cases", y "controls",
  # direction "<" (controls below cases).
  r <- roc(controls = case$y, cases = case$x, direction = "<", quiet = TRUE)
  ci <- ci.auc(r, conf.level = 0.95, method = "delong")
  list(name = case$name, x = case$x, y = case$y,
       auc = as.numeric(auc(r)), lo = ci[1], hi = ci[3])
}

fixture <- list(
  r_version = R.version.string,
  proc_version = as.character(packageVersion("pROC")),
  hodges_lehmann = lapply(hl_cases, hl_entry),
  delong_auc = lapply(auc_cases, auc_entry)
)

cat(toJSON(fixture, auto_unbox = TRUE, digits = NA, pretty = TRUE))
