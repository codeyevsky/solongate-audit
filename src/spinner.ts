import chalk from 'chalk';

const FRAMES = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];

export class Spinner {
  private interval: ReturnType<typeof setInterval> | null = null;
  private frame = 0;
  private message: string;

  constructor(message: string) {
    this.message = message;
  }

  start(): this {
    this.frame = 0;
    this.interval = setInterval(() => {
      const icon = chalk.cyan(FRAMES[this.frame % FRAMES.length]);
      process.stdout.write(`\r  ${icon} ${chalk.dim(this.message)}`);
      this.frame++;
    }, 80);
    return this;
  }

  update(message: string): void {
    this.message = message;
  }

  stop(finalMessage?: string): void {
    if (this.interval) {
      clearInterval(this.interval);
      this.interval = null;
    }
    process.stdout.write('\r\x1b[2K');
    if (finalMessage) {
      console.log(`  ${chalk.green('✔')} ${chalk.dim(finalMessage)}`);
    }
  }
}

export function withSpinner<T>(message: string, fn: () => T): T {
  const spinner = new Spinner(message);
  spinner.start();
  const result = fn();
  spinner.stop();
  return result;
}
