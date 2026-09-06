FROM ruby:3.3-slim

# sqlite3 gem needs libsqlite3, and building native gems needs a compiler
RUN apt-get update -qq && apt-get install -y --no-install-recommends \
    build-essential libsqlite3-dev git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY Gemfile Gemfile.lock ./
RUN bundle config set --local without 'development test' && \
    bundle install

COPY . .

EXPOSE 3000
CMD ["bin/rails", "server", "-b", "0.0.0.0"]
