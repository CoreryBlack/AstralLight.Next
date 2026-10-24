use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FrozenResultError;

#[derive(Clone, Debug, PartialEq)]
pub struct FrozenResult {
    fields: BTreeMap<String, Value>,
    frozen: bool,
}

impl FrozenResult {
    pub fn new(fields: BTreeMap<String, Value>) -> Self {
        Self {
            fields,
            frozen: false,
        }
    }

    pub fn freeze(&mut self) {
        self.frozen = true;
    }

    pub fn is_frozen(&self) -> bool {
        self.frozen
    }

    pub fn get(&self, key: &str) -> Option<&Value> {
        self.fields.get(key)
    }

    pub fn set_item(
        &mut self,
        key: impl Into<String>,
        value: Value,
    ) -> Result<(), FrozenResultError> {
        self.guard()?;
        self.fields.insert(key.into(), value);
        Ok(())
    }

    pub fn update(
        &mut self,
        values: impl IntoIterator<Item = (String, Value)>,
    ) -> Result<(), FrozenResultError> {
        self.guard()?;
        self.fields.extend(values);
        Ok(())
    }

    pub fn setdefault(
        &mut self,
        key: impl Into<String>,
        default: Value,
    ) -> Result<&Value, FrozenResultError> {
        self.guard()?;
        let key = key.into();
        Ok(self.fields.entry(key).or_insert(default))
    }

    pub fn delete_item(&mut self, key: &str) -> Result<Value, FrozenResultError> {
        self.guard()?;
        self.fields.remove(key).ok_or(FrozenResultError)
    }

    pub fn pop(&mut self, key: &str) -> Result<Option<Value>, FrozenResultError> {
        self.guard()?;
        Ok(self.fields.remove(key))
    }

    pub fn popitem(&mut self) -> Result<Option<(String, Value)>, FrozenResultError> {
        self.guard()?;
        let key = self.fields.keys().next_back().cloned();
        Ok(key.and_then(|key| self.fields.remove_entry(&key)))
    }

    pub fn clear(&mut self) -> Result<(), FrozenResultError> {
        self.guard()?;
        self.fields.clear();
        Ok(())
    }

    pub fn merge_assign(
        &mut self,
        values: impl IntoIterator<Item = (String, Value)>,
    ) -> Result<(), FrozenResultError> {
        self.guard()?;
        self.fields.extend(values);
        Ok(())
    }

    fn guard(&self) -> Result<(), FrozenResultError> {
        if self.frozen {
            Err(FrozenResultError)
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn result() -> FrozenResult {
        FrozenResult::new(BTreeMap::from([("status".to_owned(), json!("PASS"))]))
    }

    #[test]
    fn frozen_result_rejects_mutation_and_preserves_the_frozen_snapshot() {
        let mut frozen = result();
        frozen.freeze();
        assert!(frozen.is_frozen());

        assert_eq!(
            frozen.set_item("status", json!("FAIL")),
            Err(FrozenResultError)
        );
        assert_eq!(
            frozen.update([("status".to_owned(), json!("FAIL"))]),
            Err(FrozenResultError)
        );
        assert_eq!(frozen.pop("status"), Err(FrozenResultError));
        assert_eq!(frozen.clear(), Err(FrozenResultError));
        assert_eq!(frozen.delete_item("status"), Err(FrozenResultError));
        assert_eq!(
            frozen.setdefault("status", json!("FAIL")),
            Err(FrozenResultError)
        );
        assert_eq!(frozen.popitem(), Err(FrozenResultError));
        assert_eq!(
            frozen.merge_assign([("status".to_owned(), json!("FAIL"))]),
            Err(FrozenResultError)
        );
        assert_eq!(frozen.get("status"), Some(&json!("PASS")));
    }
}
